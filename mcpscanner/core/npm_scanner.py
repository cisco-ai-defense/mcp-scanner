# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""NPM Package Scanner.

Sibling of :class:`PyPIPackageScanner` for npm packages. Same two modes:

* ``use_docker=True`` (default): scans inside ``mcp-scanner-npm`` container.
* ``use_docker=False`` (opt-in SDK mode): downloads tarball directly from
  ``registry.npmjs.org`` via HTTPS, extracts it through
  :func:`mcpscanner.core.package_sandbox.safe_extract_tar_gz`, then runs the
  in-process :class:`JSBehavioralCodeAnalyzer`. Package code is never
  executed — only parsed.

Detection runs the same docstring-vs-behaviour alignment LLM check that
PyPI scans use, against JS / TS sources via the tree-sitter-backed
:class:`JSContextExtractor`.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from importlib import resources
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse

import httpx

from ..config.config import Config
from ..config.constants import MCPScannerConstants as CONSTANTS
from ..utils.logging_config import get_logger
from .package_sandbox import (
    PackageDownloadError,
    PackageExtractionError,
    count_source_files,
    download_archive,
    redact_argv_for_logging,
    safe_extract_archive,
    temp_workdir,
)
from .pypi_scanner import (
    DockerNotAvailableError,
    LLMNotConfiguredError,
    _assert_loop_not_running,
    _build_config_from_env,
    _build_scan_result,
    _https_get_json,
    analysis_scan_status,
)


logger = get_logger(__name__)


class NPMScanError(Exception):
    """Raised when the npm scan fails."""


class NPMPackageScanner:
    """Scan npm packages either in Docker (default) or in-process.

    Example:
        >>> scanner = NPMPackageScanner()
        >>> results = scanner.scan_package("@modelcontextprotocol/server-everything")

        >>> # SDK use, no Docker:
        >>> sdk = NPMPackageScanner(use_docker=False)
        >>> results = sdk.scan_package("some-mcp-server", version="1.2.3")
    """

    def __init__(
        self,
        image_name: Optional[str] = None,
        image_tag: Optional[str] = None,
        timeout: Optional[int] = None,
        use_docker: bool = True,
        registry_url: Optional[str] = None,
        config: Optional[Config] = None,
    ):
        """
        Args:
            image_name: Docker image name override.
            image_tag: Docker image tag override.
            timeout: Per-scan timeout in seconds (Docker mode).
            use_docker: Run inside Docker (recommended). When ``False``,
                run the SDK local path which never executes package code.
            registry_url: Override the npm registry. Defaults to
                ``https://registry.npmjs.org``. HTTP is rejected.
            config: Pre-built ``Config`` for local mode. Falls back to
                env vars if omitted.
        """
        self._image_name = image_name or CONSTANTS.NPM_DOCKER_IMAGE_NAME
        self._image_tag = image_tag or CONSTANTS.NPM_DOCKER_IMAGE_TAG
        self._timeout = timeout or CONSTANTS.NPM_SCAN_TIMEOUT
        self._full_image = f"{self._image_name}:{self._image_tag}"
        self._use_docker = use_docker
        self._registry_url = (registry_url or CONSTANTS.NPM_REGISTRY_URL).rstrip("/")
        self._config = config

    # ------------------------------------------------------------------
    # Docker plumbing (mirrors PyPI)
    # ------------------------------------------------------------------

    def check_docker(self) -> None:
        try:
            result = subprocess.run(
                ["docker", "info"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                raise DockerNotAvailableError(
                    "Docker is installed but not running. "
                    "Please start Docker Desktop or the Docker daemon.\n"
                    f"Error: {result.stderr.strip()}"
                )
        except FileNotFoundError:
            raise DockerNotAvailableError(
                "Docker is not installed. Install Docker or pass "
                "use_docker=False to the NPMPackageScanner SDK constructor."
            )
        except subprocess.TimeoutExpired:
            raise DockerNotAvailableError(
                "Docker did not respond within 10 seconds."
            )

    def _image_exists(self) -> bool:
        result = subprocess.run(
            ["docker", "image", "inspect", self._full_image],
            capture_output=True,
            text=True,
        )
        return result.returncode == 0

    def build_image(self, force: bool = False) -> None:
        if not force and self._image_exists():
            logger.info(
                "Docker image %s already exists, skipping build", self._full_image
            )
            return
        logger.info("Building Docker image %s ...", self._full_image)
        docker_dir = resources.files("mcpscanner.docker")
        with resources.as_file(docker_dir) as ctx_path:
            cmd = [
                "docker", "build",
                "-t", self._full_image,
                "-f", str(ctx_path / "Dockerfile.npm"),
                str(ctx_path),
            ]
            logger.debug("Running: %s", redact_argv_for_logging(cmd))
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=600
            )
            if result.returncode != 0:
                raise NPMScanError(
                    f"Failed to build npm Docker image:\n{result.stderr.strip()}"
                )
        logger.info("Docker image %s built successfully", self._full_image)

    # ------------------------------------------------------------------
    # Public entrypoint
    # ------------------------------------------------------------------

    def scan_package(
        self,
        package: str,
        version: Optional[str] = None,
        verbose: bool = False,
    ) -> dict:
        """Scan an npm package (synchronous).

        Args:
            package: npm package name. Scoped packages like
                ``@scope/name`` are supported.
            version: Specific version (default: latest).
            verbose: Print container stderr to host stderr (Docker mode).

        Returns:
            Scan result dict — same schema as ``PyPIPackageScanner``.

        Raises:
            DockerNotAvailableError: If Docker is required but unavailable.
            NPMScanError: If the scan fails.
            LLMNotConfiguredError: In local mode when no LLM key is set.
            RuntimeError: If called from inside an already-running event
                loop; use :meth:`scan_package_async` instead.
        """
        if self._use_docker:
            return self._scan_in_docker(package, version, verbose)
        _assert_loop_not_running("NPMPackageScanner.scan_package")
        return asyncio.run(self._scan_locally(package, version))

    async def scan_package_async(
        self,
        package: str,
        version: Optional[str] = None,
        verbose: bool = False,
    ) -> dict:
        """Async-friendly counterpart of :meth:`scan_package`. Required
        whenever the caller already lives inside an event loop."""
        if self._use_docker:
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(
                None, self._scan_in_docker, package, version, verbose
            )
        return await self._scan_locally(package, version)

    # ------------------------------------------------------------------
    # Docker mode
    # ------------------------------------------------------------------

    def _scan_in_docker(
        self, package: str, version: Optional[str], verbose: bool
    ) -> dict:
        self.check_docker()
        self.build_image()

        cmd = ["docker", "run", "--rm", "--network=bridge"]
        env_vars = {
            "LLM_API_KEY": os.environ.get("MCP_SCANNER_LLM_API_KEY", ""),
            "LLM_MODEL": os.environ.get("MCP_SCANNER_LLM_MODEL", "gpt-4o-mini"),
            "LLM_BASE_URL": os.environ.get("MCP_SCANNER_LLM_BASE_URL", ""),
            "LLM_API_VERSION": os.environ.get("MCP_SCANNER_LLM_API_VERSION", ""),
            "NPM_REGISTRY_URL": self._registry_url,
        }
        for key, value in env_vars.items():
            if value:
                cmd.extend(["-e", f"{key}={value}"])

        cmd.append(self._full_image)
        cmd.append(package)
        if version:
            cmd.extend(["--version", version])

        spec = f"{package}@{version}" if version else package
        logger.info("Scanning npm package: %s", spec)
        logger.debug("Running: %s", redact_argv_for_logging(cmd))

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self._timeout
            )
        except subprocess.TimeoutExpired:
            raise NPMScanError(
                f"npm scan timed out after {self._timeout}s. "
                f"Raise MCP_SCANNER_NPM_SCAN_TIMEOUT to allow more time."
            )

        if verbose and result.stderr:
            print(result.stderr, file=sys.stderr)

        if not result.stdout.strip():
            raise NPMScanError(
                f"no output from npm container. stderr:\n{result.stderr.strip()}"
            )

        try:
            scan_results = json.loads(result.stdout.strip())
        except json.JSONDecodeError as e:
            raise NPMScanError(
                f"invalid JSON from container: {e}\n"
                f"stdout: {result.stdout[:500]}\n"
                f"stderr: {result.stderr[:500]}"
            )

        if "error" in scan_results and scan_results.get("is_safe") is None:
            # Mirror PyPIPackageScanner._scan_in_docker: surface a typed
            # exception when the container reports a config-class failure
            # so CLI exit codes / SDK try/excepts can branch on it.
            error_code = scan_results.get("error_code", "scan_failed")
            message = scan_results.get("error", "(no error message)")
            if error_code == "llm_not_configured":
                raise LLMNotConfiguredError(message)
            raise NPMScanError(f"npm scan failed inside container: {message}")

        return scan_results

    # ------------------------------------------------------------------
    # Local (no-Docker) SDK mode
    # ------------------------------------------------------------------

    async def _scan_locally(
        self, package: str, version: Optional[str]
    ) -> dict:
        """Download → safe-extract → analyse, all in-process. Package
        code is parsed via tree-sitter; nothing is executed."""
        from .analyzers.behavioral.js_code_analyzer import JSBehavioralCodeAnalyzer

        spec = f"{package}@{version}" if version else package

        # Validate transport config before anything else; lets callers
        # catch ``http://`` registry URLs at construction-time-ish
        # without first paying for a config object.
        if not self._registry_url.lower().startswith("https://"):
            raise NPMScanError(
                f"refusing npm registry over non-TLS URL: {self._registry_url!r}"
            )

        # Fail fast on missing LLM credentials; see PyPIPackageScanner
        # for rationale.
        config = self._config or _build_config_from_env()
        if not getattr(config, "llm_provider_api_key", ""):
            raise LLMNotConfiguredError(
                "no LLM API key configured for behavioural analysis. "
                "Set MCP_SCANNER_LLM_API_KEY or pass a Config with "
                "llm_provider_api_key= ... to the scanner."
            )

        logger.warning(
            "npm local-mode SCAN spec=%s -- Docker isolation disabled; "
            "use_docker=True is recommended for untrusted packages",
            spec,
        )

        try:
            tarball_url, resolved_version, expected_digest, digest_algo = (
                self._resolve_tarball_url(package, version)
            )
        except PackageDownloadError as e:
            raise NPMScanError(str(e)) from e

        # Pin the tarball download to the same host the registry lives on
        # (plus its conventional ``*.npmjs.org`` CDN aliases) so a
        # compromised manifest can't redirect us to attacker.example.com.
        registry_host = urlparse(self._registry_url).hostname
        allowed_hosts: tuple[str, ...]
        if registry_host:
            allowed_hosts = (registry_host,)
            if registry_host == "npmjs.org" or registry_host.endswith(".npmjs.org"):
                allowed_hosts = allowed_hosts + ("npmjs.com", "npmjs.org")
        else:
            allowed_hosts = ()

        with temp_workdir(prefix="mcp-scanner-npm-") as workdir:
            download_dir = workdir / "dl"
            extract_dir = workdir / "src"
            download_dir.mkdir()
            extract_dir.mkdir()

            try:
                archive = download_archive(
                    tarball_url,
                    download_dir,
                    expected_digest=expected_digest,
                    expected_digest_algo=digest_algo,
                    allowed_hosts=allowed_hosts or None,
                )
                source_root = safe_extract_archive(archive, extract_dir)
            except (PackageDownloadError, PackageExtractionError) as e:
                raise NPMScanError(
                    f"failed to fetch/extract {spec}: {e}"
                ) from e

            analyzer = JSBehavioralCodeAnalyzer(config)
            findings = await analyzer.analyze(str(source_root), {})

            js_files = self._count_js_files(source_root)
            return _build_scan_result(
                ecosystem="npm",
                package=package,
                resolved_version=resolved_version,
                source_root=source_root,
                files_scanned=js_files,
                findings=findings,
                scan_status=analysis_scan_status(analyzer, findings),
            )

    # ------------------------------------------------------------------
    # Registry lookup
    # ------------------------------------------------------------------

    def _resolve_tarball_url(
        self, package: str, version: Optional[str]
    ) -> Tuple[str, str, Optional[str], Optional[str]]:
        """Look up the tarball URL via the npm registry HTTP API.

        Scoped packages (``@scope/name``) need their slash URL-encoded.

        Returns ``(tarball_url, resolved_version, expected_digest,
        digest_algo)`` where:

        * ``expected_digest`` is either the SRI-formatted ``integrity``
          string the registry publishes (e.g. ``sha512-<base64>``) or a
          hex digest from the legacy ``shasum`` field.
        * ``digest_algo`` is ``None`` when ``expected_digest`` is an SRI
          string (parsed out of the prefix) and ``"sha1"`` when falling
          back to ``shasum``. SHA-1 is weak but still tamper-evident
          against accidental corruption; refusing the download outright
          here would break too many older packages.

        :meth:`_scan_locally` validates the registry URL is HTTPS before
        calling us, but other future call sites might not, so we keep a
        cheap one-line defensive check here. ``_https_get_json`` would
        also raise downstream, but the error there is harder to act on.
        """
        if not self._registry_url.lower().startswith("https://"):
            raise PackageDownloadError(
                f"refusing npm registry over non-TLS URL: {self._registry_url!r}"
            )

        encoded = package.replace("/", "%2F") if package.startswith("@") else package
        if version:
            meta_url = f"{self._registry_url}/{encoded}/{version}"
        else:
            meta_url = f"{self._registry_url}/{encoded}/latest"

        # Restrict the manifest lookup to the registry host the scanner
        # was configured with. We deliberately don't broaden this to the
        # tarball host allow-list (set up below) — manifests only ever
        # come from the registry, and tarballs only ever come from the
        # CDN; a CDN host appearing on the manifest hop would be a
        # misconfiguration we want to fail on.
        registry_host = urlparse(self._registry_url).hostname
        manifest_hosts = (registry_host,) if registry_host else None
        try:
            manifest = _https_get_json(
                meta_url,
                user_agent="mcp-scanner/npm",
                timeout=CONSTANTS.PACKAGE_DOWNLOAD_TIMEOUT,
                allowed_hosts=manifest_hosts,
            )
        except PackageDownloadError:
            raise
        except httpx.HTTPError as e:
            raise PackageDownloadError(
                f"failed to fetch npm manifest for {package}: {e}"
            ) from e
        except json.JSONDecodeError as e:
            raise PackageDownloadError(
                f"npm registry returned invalid JSON for {package}: {e}"
            ) from e

        resolved_version = manifest.get("version") or version or "unknown"
        dist = manifest.get("dist") or {}
        tarball = dist.get("tarball")
        if not tarball:
            raise PackageDownloadError(
                f"no tarball URL for {package}@{resolved_version}"
            )

        integrity = dist.get("integrity")
        if integrity:
            # SRI string; download_archive parses the algo prefix.
            return tarball, resolved_version, integrity, None
        shasum = dist.get("shasum")
        if shasum:
            return tarball, resolved_version, shasum, "sha1"
        return tarball, resolved_version, None, None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _count_js_files(source_root) -> int:
        """Count source files we'd hand to the JS analyzer. Mirrors the
        analyzer's own exclusion list — same helper the Docker entrypoint
        uses — so the ``js_files_scanned`` value is identical across
        execution modes."""
        from .analyzers.behavioral.js_code_analyzer import (
            _JS_EXTENSIONS,
            _SKIP_DIRS,
        )

        return count_source_files(
            source_root,
            extensions=_JS_EXTENSIONS,
            skip_dirs=_SKIP_DIRS,
        )
