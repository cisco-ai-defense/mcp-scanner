# Copyright 2025 Cisco Systems, Inc. and its affiliates
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

"""PyPI Package Scanner.

Two execution modes:

1. ``use_docker=True`` (default): downloads and analyses the package inside
   an isolated Docker container, the recommended path for any untrusted
   source. Behaviour is unchanged from the original implementation.

2. ``use_docker=False`` (opt-in, SDK-only): downloads the package source
   distribution directly to a tempdir on the host using the safe-extraction
   primitives in :mod:`mcpscanner.core.package_sandbox`, then runs the
   in-process behavioural analyzer over the extracted files. Code from the
   package is **never executed** — only parsed. This mode exists for SDK
   users who cannot run Docker (CI shared runners, sandboxed CI/CD, etc.),
   and intentionally rejects HTTP and oversize archives.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from importlib import resources
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

import httpx

from ..config.config import Config
from ..config.constants import MCPScannerConstants as CONSTANTS
from ..utils.logging_config import get_logger
from .package_sandbox import (
    PackageDownloadError,
    PackageExtractionError,
    _next_redirect_target,
    _validate_https_url,
    count_source_files,
    download_archive,
    redact_argv_for_logging,
    safe_extract_archive,
    temp_workdir,
)

logger = get_logger(__name__)


# Hosts the PyPI tarball URL must resolve to. ``files.pythonhosted.org``
# is the canonical CDN; ``pypi.org`` is for metadata only but we list it
# defensively. SDK users on a private index can override via env if
# needed in a future patch.
_PYPI_TARBALL_HOSTS: tuple[str, ...] = (
    "files.pythonhosted.org",
    "pypi.org",
)


class DockerNotAvailableError(Exception):
    """Raised when Docker is not installed or not running."""


class PyPIScanError(Exception):
    """Raised when the PyPI scan fails."""


class LLMNotConfiguredError(Exception):
    """Raised by the local (no-Docker) path when no LLM API key is set.

    Returning ``is_safe=True`` for an un-analysed package would lie to the
    caller, so the SDK refuses to run instead. Set
    ``MCP_SCANNER_LLM_API_KEY`` (or pass a pre-built :class:`Config`) and
    retry.
    """


def _assert_loop_not_running(context: str) -> None:
    """Refuse to call ``asyncio.run`` from inside an already-running loop.

    The previous implementation called ``asyncio.run`` unconditionally,
    which crashed every SDK caller that lived inside an event loop
    (FastAPI handlers, jupyter cells, etc.). The async entrypoint is the
    supported alternative; raise a clear error rather than silently
    deadlocking.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return
    raise RuntimeError(
        f"{context} was called from inside a running asyncio event loop. "
        f"Use the async entrypoint (e.g. await scan_package_async(...)) "
        f"or run this call from a non-async context."
    )


class PyPIPackageScanner:
    """Scan PyPI packages either in Docker (default) or in-process.

    Example:
        >>> scanner = PyPIPackageScanner()
        >>> results = scanner.scan_package("flask")            # Docker
        >>> sdk = PyPIPackageScanner(use_docker=False)
        >>> results = sdk.scan_package("flask", version="3.0.0")  # local
    """

    def __init__(
        self,
        image_name: Optional[str] = None,
        image_tag: Optional[str] = None,
        timeout: Optional[int] = None,
        use_docker: bool = True,
        config: Optional[Config] = None,
    ):
        """
        Args:
            image_name: Override the Docker image name.
            image_tag: Override the Docker image tag.
            timeout: Per-scan timeout in seconds (Docker mode only; local
                mode is bounded by network + analyzer timeouts).
            use_docker: When ``False`` skip the container entirely and run
                in-process. Intended for SDK users on shared CI runners or
                in environments where Docker isn't available. Local mode
                rejects HTTP URLs and bounds archive size — see
                :mod:`mcpscanner.core.package_sandbox`.
            config: Optional pre-built ``Config``. Only used in local mode.
                When omitted the scanner builds one from the standard
                ``MCP_SCANNER_LLM_*`` environment variables.
        """
        self._image_name = image_name or CONSTANTS.DOCKER_IMAGE_NAME
        self._image_tag = image_tag or CONSTANTS.DOCKER_IMAGE_TAG
        self._timeout = timeout or CONSTANTS.PYPI_SCAN_TIMEOUT
        self._full_image = f"{self._image_name}:{self._image_tag}"
        self._use_docker = use_docker
        self._config = config

    # ------------------------------------------------------------------
    # Docker plumbing
    # ------------------------------------------------------------------

    def check_docker(self) -> None:
        """Verify Docker is installed and running.

        Raises:
            DockerNotAvailableError: If Docker is not available.
        """
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
                "Docker is not installed. "
                "PyPI package scanning requires Docker for sandboxed execution. "
                "Install Docker from https://docs.docker.com/get-docker/"
            )
        except subprocess.TimeoutExpired:
            raise DockerNotAvailableError(
                "Docker did not respond within 10 seconds. "
                "Please check that Docker is running properly."
            )

    def _image_exists(self) -> bool:
        """Check if the scanner Docker image already exists."""
        result = subprocess.run(
            ["docker", "image", "inspect", self._full_image],
            capture_output=True,
            text=True,
        )
        return result.returncode == 0

    def build_image(self, force: bool = False) -> None:
        """Build the scanner Docker image if it doesn't exist.

        Args:
            force: Rebuild even if the image already exists.
        """
        if not force and self._image_exists():
            logger.info("Docker image %s already exists, skipping build", self._full_image)
            return

        logger.info("Building Docker image %s ...", self._full_image)

        docker_dir = resources.files("mcpscanner.docker")
        with resources.as_file(docker_dir) as ctx_path:
            cmd = [
                "docker", "build",
                "-t", self._full_image,
                "-f", str(ctx_path / "Dockerfile"),
                str(ctx_path),
            ]

            logger.debug("Running: %s", redact_argv_for_logging(cmd))
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,
            )

            if result.returncode != 0:
                raise PyPIScanError(
                    f"Failed to build Docker image:\n{result.stderr.strip()}"
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
        """Scan a PyPI package (synchronous).

        Args:
            package: PyPI package name (e.g., "flask").
            version: Specific version to scan (default: latest).
            verbose: Print container stderr to host stderr (Docker mode).

        Returns:
            Dictionary with scan results.

        Raises:
            DockerNotAvailableError: If Docker is required but unavailable.
            PyPIScanError: If the scan fails.
            LLMNotConfiguredError: In local mode when no LLM key is set.
            RuntimeError: If called from inside an already-running event
                loop; use :meth:`scan_package_async` instead.
        """
        if self._use_docker:
            return self._scan_in_docker(package, version, verbose)
        _assert_loop_not_running("PyPIPackageScanner.scan_package")
        return asyncio.run(self._scan_locally(package, version))

    async def scan_package_async(
        self,
        package: str,
        version: Optional[str] = None,
        verbose: bool = False,
    ) -> dict:
        """Async-friendly counterpart of :meth:`scan_package`.

        SDK consumers running inside an event loop (FastAPI handlers,
        notebooks, etc.) must use this entrypoint so the analyzer's own
        ``async def`` calls compose with their loop. Docker mode shells
        out via ``subprocess.run``; we run that on the default executor
        so the calling loop isn't blocked for the duration of the
        container scan.
        """
        if self._use_docker:
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(
                None, self._scan_in_docker, package, version, verbose
            )
        return await self._scan_locally(package, version)

    # ------------------------------------------------------------------
    # Docker mode (unchanged)
    # ------------------------------------------------------------------

    def _scan_in_docker(
        self, package: str, version: Optional[str], verbose: bool
    ) -> dict:
        self.check_docker()
        self.build_image()

        cmd = [
            "docker", "run",
            "--rm",
            "--network=bridge",
        ]

        env_vars = {
            "LLM_API_KEY": os.environ.get("MCP_SCANNER_LLM_API_KEY", ""),
            "LLM_MODEL": os.environ.get("MCP_SCANNER_LLM_MODEL", "gpt-4o-mini"),
            "LLM_BASE_URL": os.environ.get("MCP_SCANNER_LLM_BASE_URL", ""),
            "LLM_API_VERSION": os.environ.get("MCP_SCANNER_LLM_API_VERSION", ""),
        }
        for key, value in env_vars.items():
            if value:
                cmd.extend(["-e", f"{key}={value}"])

        cmd.append(self._full_image)
        cmd.append(package)
        if version:
            cmd.extend(["--version", version])

        spec = f"{package}=={version}" if version else package
        logger.info("Scanning PyPI package: %s", spec)
        logger.debug("Running: %s", redact_argv_for_logging(cmd))

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self._timeout,
            )
        except subprocess.TimeoutExpired:
            raise PyPIScanError(
                f"Scan timed out after {self._timeout}s. "
                f"Increase timeout via MCP_SCANNER_PYPI_SCAN_TIMEOUT env var."
            )

        if verbose and result.stderr:
            print(result.stderr, file=sys.stderr)

        if not result.stdout.strip():
            raise PyPIScanError(
                f"No output from container. stderr:\n{result.stderr.strip()}"
            )

        try:
            scan_results = json.loads(result.stdout.strip())
        except json.JSONDecodeError as e:
            raise PyPIScanError(
                f"Invalid JSON from container: {e}\n"
                f"stdout: {result.stdout[:500]}\n"
                f"stderr: {result.stderr[:500]}"
            )

        if "error" in scan_results and scan_results.get("is_safe") is None:
            # Map the container's stable error_code back to typed
            # exceptions so callers (CLI exit codes, SDK handlers) can
            # distinguish a missing LLM key from a transient scan failure.
            error_code = scan_results.get("error_code", "scan_failed")
            message = scan_results.get("error", "(no error message)")
            if error_code == "llm_not_configured":
                raise LLMNotConfiguredError(message)
            raise PyPIScanError(f"Scan failed inside container: {message}")

        return scan_results

    # ------------------------------------------------------------------
    # Local (no-Docker) SDK mode
    # ------------------------------------------------------------------

    async def _scan_locally(
        self, package: str, version: Optional[str]
    ) -> dict:
        """In-process PyPI scan: download → safe-extract → analyse.

        Code from the downloaded package is never executed. Only the
        behavioural analyzer's static AST/dataflow + LLM alignment check
        runs on the extracted source tree.
        """
        from .analyzers.behavioral.code_analyzer import BehavioralCodeAnalyzer

        spec = f"{package}=={version}" if version else package

        # Fail fast on missing LLM credentials -- otherwise the analyzer
        # would silently no-op and we'd return is_safe=True for a
        # package we never actually analysed.
        config = self._config or _build_config_from_env()
        if not getattr(config, "llm_provider_api_key", ""):
            raise LLMNotConfiguredError(
                "no LLM API key configured for behavioural analysis. "
                "Set MCP_SCANNER_LLM_API_KEY or pass a Config with "
                "llm_provider_api_key= ... to the scanner."
            )

        logger.warning(
            "pypi local-mode SCAN spec=%s -- Docker isolation disabled; "
            "use_docker=True is recommended for untrusted packages",
            spec,
        )

        try:
            url, resolved_version, expected_digest = (
                self._resolve_pypi_sdist_url(package, version)
            )
        except PackageDownloadError as e:
            raise PyPIScanError(str(e)) from e

        with temp_workdir(prefix="mcp-scanner-pypi-") as workdir:
            download_dir = workdir / "dl"
            extract_dir = workdir / "src"
            download_dir.mkdir()
            extract_dir.mkdir()

            try:
                archive = download_archive(
                    url,
                    download_dir,
                    expected_digest=expected_digest,
                    expected_digest_algo="sha256" if expected_digest else None,
                    allowed_hosts=_PYPI_TARBALL_HOSTS,
                )
                source_root = safe_extract_archive(archive, extract_dir)
            except (PackageDownloadError, PackageExtractionError) as e:
                raise PyPIScanError(
                    f"failed to fetch/extract {spec}: {e}"
                ) from e

            analyzer = BehavioralCodeAnalyzer(config)
            findings = await analyzer.analyze(str(source_root), {})

            # Use the shared counter (skips hidden dirs) so the value
            # matches both the Docker entrypoint and the analyzer's own
            # ``_find_python_files`` which ignores hidden/``__pycache__``
            # paths. A plain ``rglob("*.py")`` over-counted files the
            # analyzer never actually looked at.
            # Match the behavioural analyzer's own exclusions
            # (``_find_source_files`` skips these) so the reported
            # ``python_files_scanned`` never counts files the analyzer
            # never looked at. Hidden dirs are dropped by ``skip_hidden``.
            py_files = count_source_files(
                source_root,
                extensions=(".py",),
                skip_dirs=("__pycache__", "node_modules"),
            )

            return _build_scan_result(
                ecosystem="pypi",
                package=package,
                resolved_version=resolved_version,
                source_root=source_root,
                files_scanned=py_files,
                findings=findings,
                scan_status=analysis_scan_status(analyzer, findings),
            )

    def _resolve_pypi_sdist_url(
        self, package: str, version: Optional[str]
    ) -> tuple[str, str, Optional[str]]:
        """Look up the sdist tarball URL via the PyPI JSON API.

        Returns ``(url, resolved_version, expected_sha256_hex)`` where
        the digest comes from ``digests.sha256`` in the index response
        and is later verified during download.
        """
        meta_url = (
            f"{CONSTANTS.PYPI_INDEX_URL.rstrip('/')}/{package}/{version}/json"
            if version
            else f"{CONSTANTS.PYPI_INDEX_URL.rstrip('/')}/{package}/json"
        )
        if not meta_url.lower().startswith("https://"):
            raise PackageDownloadError(
                f"refusing PyPI index over non-TLS URL: {meta_url!r}"
            )

        try:
            meta = _https_get_json(
                meta_url,
                user_agent="mcp-scanner/pypi",
                timeout=CONSTANTS.PACKAGE_DOWNLOAD_TIMEOUT,
                allowed_hosts=("pypi.org",),
            )
        except PackageDownloadError:
            raise
        except httpx.HTTPError as e:
            raise PackageDownloadError(
                f"failed to fetch PyPI metadata for {package}: {e}"
            ) from e
        except json.JSONDecodeError as e:
            raise PackageDownloadError(
                f"PyPI returned invalid JSON for {package}: {e}"
            ) from e

        info = meta.get("info") or {}
        resolved_version = (info.get("version") or version or "unknown")
        urls = meta.get("urls") or []
        sdist = next(
            (u for u in urls if u.get("packagetype") == "sdist"),
            None,
        )
        if sdist is None or not sdist.get("url"):
            raise PackageDownloadError(
                f"no source distribution found for {package} {resolved_version}"
            )
        digests = sdist.get("digests") or {}
        expected = digests.get("sha256")
        return sdist["url"], resolved_version, expected


# ----------------------------------------------------------------------
# Shared result/Config helpers (used by both PyPI and NPM scanners)
# ----------------------------------------------------------------------


def _build_config_from_env() -> Config:
    """Construct a :class:`Config` from the standard scanner env vars. The
    SDK no-Docker path uses this when the caller didn't pass one in."""
    api_key = os.environ.get(CONSTANTS.ENV_LLM_API_KEY, "")
    return Config(
        llm_provider_api_key=api_key,
        llm_model=os.environ.get(
            CONSTANTS.ENV_LLM_MODEL, CONSTANTS.DEFAULT_LLM_MODEL
        ),
        llm_base_url=os.environ.get(CONSTANTS.ENV_LLM_BASE_URL, "") or "",
        llm_api_version=os.environ.get(CONSTANTS.ENV_LLM_API_VERSION, "") or "",
    )


def _https_get_json(
    url: str,
    *,
    user_agent: str,
    timeout: int,
    allowed_hosts: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    """HTTPS-only JSON GET with manual redirect handling.

    Forbids HTTP at any hop in the redirect chain so a misconfigured CDN
    can't quietly downgrade us to clear-text. Used for both PyPI and npm
    metadata lookups so the policy lives in one place.

    ``allowed_hosts``: optional registry host allow-list. When provided
    we enforce it on the initial URL *and* on every redirect target,
    matching the policy applied in :func:`download_archive`. Callers
    should always pass this for production paths; ``None`` is only
    intended for tests or one-off scripts where the registry isn't
    known up front.
    """
    # Validate the seed URL for scheme and (optional) host allow-list.
    # The ParseResult itself isn't needed downstream — we only care about
    # the side effect (raising on a violation). Each redirect hop is
    # revalidated by ``_next_redirect_target``.
    _validate_https_url(url, allowed_hosts)

    with httpx.Client(
        timeout=timeout,
        follow_redirects=False,
        headers={"User-Agent": user_agent},
    ) as client:
        current = url
        for _hop in range(10):
            resp = client.get(current)
            if resp.is_redirect:
                current, _ = _next_redirect_target(
                    current, resp, allowed_hosts
                )
                continue
            resp.raise_for_status()
            return resp.json()
        raise PackageDownloadError(f"too many redirects fetching {url!r}")


def analysis_scan_status(analyzer: Any, findings: Sequence[Any]) -> str:
    """Decide whether a behavioural scan actually completed or whether it
    was degraded by analyzer-infrastructure failures (LLM unreachable,
    prompt build crash, response-validation errors, etc.).

    Two distinct failure tallies feed this decision:

    * The alignment orchestrator swallows per-function failures and returns
      ``None`` for that function, recording a ``skipped_error``. A scan
      where every function failed at the LLM stage surfaces zero findings.
    * The analyzer itself swallows failures that happen *before* the
      orchestrator is reached — file-read errors, AST/context-extraction
      crashes, an unavailable tree-sitter parser, or a top-level crash —
      tracking them in ``analysis_errors``. Without this, a package whose
      sources never parsed would surface zero findings and be misread as
      clean.

    Either tally, combined with zero findings, means we never actually
    analysed the package and therefore must not report ``is_safe=True``.

    Rules:

    * If we surfaced any findings, the scan is ``completed`` regardless of
      partial errors — the findings stand on their own and ``is_safe`` is
      already ``False``.
    * If we surfaced no findings *and* either tally is non-zero, the result
      is unreliable → ``error``. The caller maps this to ``is_safe=None``.
    * Otherwise (no findings, no errors — nothing to analyse or everything
      aligned cleanly) the scan is ``completed``.

    The analyzer is duck-typed: any object exposing
    ``alignment_orchestrator.get_statistics()`` and/or an
    ``analysis_errors`` int works, which covers both the Python and JS
    behavioural analyzers. Reading the stats is wrapped defensively so a
    bookkeeping glitch can't crash a scan, but a glitch there still lets
    the ``analysis_errors`` tally (read separately) drive the decision.
    """
    if findings:
        return "completed"
    error_tally = 0
    try:
        stats = analyzer.alignment_orchestrator.get_statistics()
        error_tally += int(stats.get("skipped_error", 0))
    except Exception:  # noqa: BLE001 - never let stats bookkeeping fail a scan
        pass
    try:
        error_tally += int(getattr(analyzer, "analysis_errors", 0) or 0)
    except (TypeError, ValueError):  # pragma: no cover - defensive
        pass
    return "error" if error_tally > 0 else "completed"


def _build_scan_result(
    *,
    ecosystem: str,
    package: str,
    resolved_version: str,
    source_root: Path,
    files_scanned: int,
    findings: List[Any],
    scan_status: str = "completed",
) -> Dict[str, Any]:
    """Render a :class:`SecurityFinding` list into the JSON shape the
    Docker entrypoint already emits, so CLI and SDK callers see the same
    schema regardless of execution mode.

    The ``files_scanned`` count is also surfaced under an ecosystem-
    specific key so downstream callers don't have to remember to pop a
    field that doesn't apply to their language.
    """
    serialised: List[Dict[str, Any]] = []
    for f in findings:
        serialised.append(
            {
                "analyzer": f.analyzer.lower() if getattr(f, "analyzer", None) else "behavioral",
                "severity": getattr(f, "severity", "UNKNOWN"),
                "threat_category": getattr(f, "threat_category", None),
                "summary": getattr(f, "summary", ""),
                "details": getattr(f, "details", None) or {},
            }
        )
    ecosystem_field = (
        "python_files_scanned"
        if ecosystem == "pypi"
        else "js_files_scanned"
        if ecosystem == "npm"
        else f"{ecosystem}_files_scanned"
    )
    result: Dict[str, Any] = {
        "ecosystem": ecosystem,
        "package": package,
        "version": resolved_version,
        "source_dir": str(source_root),
        "files_scanned": files_scanned,
        ecosystem_field: files_scanned,
        "total_findings": len(serialised),
        "behavioral_findings": len(serialised),
        "is_safe": len(serialised) == 0 if scan_status == "completed" else None,
        "scan_status": scan_status,
        "findings": serialised,
    }
    return result
