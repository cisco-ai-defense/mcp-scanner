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

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

import httpx

from ..config.config import Config
from ..config.constants import MCPScannerConstants as CONSTANTS
from ..utils.logging_config import get_logger
from .analyzers.base import is_infrastructure_error, reportable_findings
from .docker_build import docker_run_hardening_flags
from .package_scanner_base import (  # noqa: F401  (DockerNotAvailableError re-exported for SDK importers)
    DockerNotAvailableError,
    EcosystemProfile,
    PackageScannerBase,
    assert_loop_not_running,
)
from .package_sandbox import (
    PackageDownloadError,
    PackageExtractionError,
    _next_redirect_target,
    _validate_https_url,
    count_source_files,
    download_archive,
    pypi_index_allowed_hosts,
    pypi_tarball_allowed_hosts,
    redact_argv_for_logging,
    safe_extract_archive,
    temp_workdir,
    validate_pypi_package_name,
)

logger = get_logger(__name__)


class PyPIScanError(Exception):
    """Raised when the PyPI scan fails."""


class LLMNotConfiguredError(Exception):
    """Raised by the local (no-Docker) path when no LLM API key is set.

    Returning ``is_safe=True`` for an un-analysed package would lie to the
    caller, so the SDK refuses to run instead. Set
    ``MCP_SCANNER_LLM_API_KEY`` (or pass a pre-built :class:`Config`) and
    retry.
    """


def _validate_pypi_package_or_raise(package: str) -> None:
    try:
        validate_pypi_package_name(package)
    except PackageDownloadError as exc:
        raise PyPIScanError(str(exc)) from exc


def raise_if_unreliable_package_scan(
    result: dict,
    error_cls: type[Exception] = PyPIScanError,
) -> dict:
    """Reject degraded scan payloads that must not be read as safe.

    Docker and local SDK paths share this guard so callers get a
    consistent exception when ``scan_status == "error"``.
    """
    if result.get("scan_status") == "error" and result.get("is_safe") is None:
        message = result.get("error") or (
            "package scan could not be completed reliably: analysis "
            "infrastructure failed (zero findings is not a safe verdict)"
        )
        raise error_cls(message)
    return result


#: Retained for importers predating the move to ``package_scanner_base``.
_assert_loop_not_running = assert_loop_not_running

PYPI_PROFILE = EcosystemProfile(
    name="pypi",
    dockerfile="Dockerfile",
    default_image_name=CONSTANTS.DOCKER_IMAGE_NAME,
    default_timeout=CONSTANTS.PYPI_SCAN_TIMEOUT,
    scan_error=PyPIScanError,
    docker_missing_hint=(
        "PyPI package scanning requires Docker for sandboxed execution. "
        "Install Docker from https://docs.docker.com/get-docker/"
    ),
    docker_unresponsive_hint=" Please check that Docker is running properly.",
    build_failure_subject="Docker image",
)


class PyPIPackageScanner(PackageScannerBase):
    """Scan PyPI packages either in Docker (default) or in-process.

    Docker lifecycle and entrypoint dispatch come from
    :class:`~mcpscanner.core.package_scanner_base.PackageScannerBase`; what
    is PyPI-specific is archive resolution and the Python analyzer.

    Example:
        >>> scanner = PyPIPackageScanner()
        >>> results = scanner.scan_package("flask")            # Docker
        >>> sdk = PyPIPackageScanner(use_docker=False)
        >>> results = sdk.scan_package("flask", version="3.0.0")  # local
    """

    PROFILE = PYPI_PROFILE

    @staticmethod
    def _validate_package(package: str) -> None:
        _validate_pypi_package_or_raise(package)

    # ------------------------------------------------------------------
    # Docker mode
    # ------------------------------------------------------------------

    def _scan_in_docker(
        self, package: str, version: Optional[str], verbose: bool
    ) -> dict:
        self.check_docker()
        self.build_image()

        cmd = [
            "docker",
            "run",
            "--rm",
            "--network=bridge",
            *docker_run_hardening_flags(),
        ]

        env_vars = {
            "LLM_API_KEY": os.environ.get("MCP_SCANNER_LLM_API_KEY", ""),
            "LLM_MODEL": os.environ.get(
                "MCP_SCANNER_LLM_MODEL", CONSTANTS.DEFAULT_LLM_MODEL
            ),
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

        if (
            scan_results.get("scan_status") == "error"
            and scan_results.get("is_safe") is None
        ):
            raise PyPIScanError(
                scan_results.get("error")
                or (
                    "Scan could not be completed reliably: analysis infrastructure "
                    "failed for every function (zero findings is not a safe verdict)."
                )
            )

        return scan_results

    # ------------------------------------------------------------------
    # Local (no-Docker) SDK mode
    # ------------------------------------------------------------------

    async def _scan_locally(self, package: str, version: Optional[str]) -> dict:
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
            url, resolved_version, expected_digest = self._resolve_pypi_archive_url(
                package, version
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
                    allowed_hosts=pypi_tarball_allowed_hosts(CONSTANTS.PYPI_INDEX_URL),
                )
                source_root = safe_extract_archive(archive, extract_dir, only_dirs=True)
            except (PackageDownloadError, PackageExtractionError) as e:
                raise PyPIScanError(f"failed to fetch/extract {spec}: {e}") from e

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

            return raise_if_unreliable_package_scan(
                _build_scan_result(
                    ecosystem="pypi",
                    package=package,
                    resolved_version=resolved_version,
                    source_root=source_root,
                    files_scanned=py_files,
                    findings=findings,
                    scan_status=analysis_scan_status(analyzer, findings),
                )
            )

    def _resolve_pypi_archive_url(
        self, package: str, version: Optional[str]
    ) -> tuple[str, str, Optional[str]]:
        return resolve_pypi_archive_url(package, version)

    def _resolve_pypi_sdist_url(
        self, package: str, version: Optional[str]
    ) -> tuple[str, str, Optional[str]]:
        """Backward-compatible alias for :meth:`_resolve_pypi_archive_url`."""
        return self._resolve_pypi_archive_url(package, version)


def resolve_pypi_archive_url(
    package: str,
    version: Optional[str],
    *,
    index_url: Optional[str] = None,
) -> tuple[str, str, Optional[str]]:
    """Look up a PyPI archive URL via the JSON API.

    Prefers source distributions; falls back to wheels when no sdist
    is published (wheel-only packages). Returns
    ``(url, resolved_version, expected_sha256_hex)`` where the digest
    comes from ``digests.sha256`` in the index response.
    """
    index = (index_url or CONSTANTS.PYPI_INDEX_URL).rstrip("/")
    meta_url = (
        f"{index}/{package}/{version}/json" if version else f"{index}/{package}/json"
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
            allowed_hosts=pypi_index_allowed_hosts(index),
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
    resolved_version = info.get("version") or version or "unknown"
    urls = meta.get("urls") or []

    def _pick(packagetype: str) -> Optional[dict]:
        return next(
            (u for u in urls if u.get("packagetype") == packagetype and u.get("url")),
            None,
        )

    archive = _pick("sdist") or _pick("bdist_wheel")
    if archive is None:
        raise PackageDownloadError(
            f"no source distribution or wheel found for "
            f"{package} {resolved_version}"
        )
    digests = archive.get("digests") or {}
    expected = digests.get("sha256")
    return archive["url"], resolved_version, expected


# ----------------------------------------------------------------------
# Shared result/Config helpers (used by both PyPI and NPM scanners)
# ----------------------------------------------------------------------


def _build_config_from_env() -> Config:
    """Construct a :class:`Config` from the standard scanner env vars. The
    SDK no-Docker path uses this when the caller didn't pass one in."""
    api_key = os.environ.get(CONSTANTS.ENV_LLM_API_KEY, "")
    return Config(
        llm_provider_api_key=api_key,
        llm_model=os.environ.get(CONSTANTS.ENV_LLM_MODEL, CONSTANTS.DEFAULT_LLM_MODEL),
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
                current, _ = _next_redirect_target(current, resp, allowed_hosts)
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

    * An ``ANALYZER INFRASTRUCTURE`` finding *is* the report that the scan
      crashed, so it forces ``error`` — otherwise the analyzer's own
      failure notice would be read as proof that the analyzer ran.
    * If we surfaced any other *reportable* findings, the scan is
      ``completed`` regardless of partial errors — the findings stand on
      their own and ``is_safe`` is already ``False``. SAFE placeholders
      don't count: they are emitted once per scanned capability, so
      counting them would mark every degraded scan ``completed`` and hand
      back ``is_safe=True``.
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
    if any(is_infrastructure_error(f) for f in findings):
        return "error"
    if _reportable_findings(findings):
        return "completed"
    error_tally = 0
    stats_ok = False
    try:
        stats = analyzer.alignment_orchestrator.get_statistics()
        error_tally += int(stats.get("skipped_error", 0))
        stats_ok = True
    except Exception:  # noqa: BLE001 - never let stats bookkeeping fail a scan
        pass
    try:
        error_tally += int(getattr(analyzer, "analysis_errors", 0) or 0)
    except (TypeError, ValueError):  # pragma: no cover - defensive
        pass
    if error_tally > 0:
        return "error"
    if not stats_ok:
        return "error"
    return "completed"


def _reportable_findings(findings: Sequence[Any]) -> List[Any]:
    """Drop benign SAFE placeholders; keep UNKNOWN for inconclusive scans."""
    return reportable_findings(findings)


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
    reportable = _reportable_findings(findings)
    for f in reportable:
        serialised.append(
            {
                "analyzer": (
                    f.analyzer.lower() if getattr(f, "analyzer", None) else "behavioral"
                ),
                "severity": getattr(f, "severity", "UNKNOWN"),
                "threat_category": getattr(f, "threat_category", None),
                "summary": getattr(f, "summary", ""),
                "details": getattr(f, "details", None) or {},
            }
        )
    ecosystem_field = (
        "python_files_scanned"
        if ecosystem == "pypi"
        else "js_files_scanned" if ecosystem == "npm" else f"{ecosystem}_files_scanned"
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
