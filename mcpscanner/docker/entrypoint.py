#!/usr/bin/env python3
"""
Entrypoint script for the MCP Scanner PyPI Docker container.

Downloads a PyPI package, extracts it, and runs behavioral analysis
and vulnerable packages audit inside an isolated container.

All results are printed as JSON to stdout. Logs go to stderr.
"""

import argparse
import asyncio
import glob
import json
import logging
import os
import subprocess
import sys
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s: %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("pypi-scanner")

DOWNLOAD_DIR = "/tmp/download"
EXTRACT_DIR = "/tmp/package"


def download_package(package: str, version: str | None) -> Path:
    """Download a PyPI package, preferring source dist but falling back to wheel."""
    os.makedirs(DOWNLOAD_DIR, exist_ok=True)

    spec = f"{package}=={version}" if version else package
    logger.info("Downloading %s", spec)

    # Try source distribution first
    cmd_sdist = [
        sys.executable, "-m", "pip", "download",
        "--no-deps",
        "--no-binary", ":all:",
        "--dest", DOWNLOAD_DIR,
        spec,
    ]
    result = subprocess.run(cmd_sdist, capture_output=True, text=True)

    if result.returncode != 0:
        logger.warning("Source dist unavailable, downloading wheel instead")
        # Clear any partial downloads
        for f in Path(DOWNLOAD_DIR).iterdir():
            f.unlink()

        cmd_wheel = [
            sys.executable, "-m", "pip", "download",
            "--no-deps",
            "--dest", DOWNLOAD_DIR,
            spec,
        ]
        result = subprocess.run(cmd_wheel, capture_output=True, text=True)
        if result.returncode != 0:
            logger.error("pip download failed:\n%s", result.stderr)
            raise RuntimeError(f"Failed to download {spec}: {result.stderr.strip()}")

    archives = (
        glob.glob(os.path.join(DOWNLOAD_DIR, "*.tar.gz"))
        + glob.glob(os.path.join(DOWNLOAD_DIR, "*.zip"))
        + glob.glob(os.path.join(DOWNLOAD_DIR, "*.whl"))
    )
    if not archives:
        raise RuntimeError(f"No archive found after downloading {spec}")

    archive = Path(archives[0])
    logger.info("Downloaded: %s", archive.name)
    return archive


def extract_package(archive: Path) -> Path:
    """Extract the downloaded archive using the shared safe-extraction
    helpers so the byte / file-count caps and traversal protections are
    applied here too. Docker network isolation already contains a hostile
    payload, but using the same hardened path everywhere removes a
    forking maintenance burden.

    ``only_dirs=True`` preserves the historical PyPI Docker behaviour of
    selecting the single ``<name>-<version>/`` extraction subdir even
    when pip drops sibling files (``README``, ``LICENSE``, ``setup.cfg``)
    at the extraction root. Without it some sdists would silently shift
    the analyzer to scan ``EXTRACT_DIR`` instead of the package root,
    changing the ``python_files_scanned`` count for the same input.
    """
    from mcpscanner.core.package_sandbox import safe_extract_archive

    os.makedirs(EXTRACT_DIR, exist_ok=True)
    extract_path = safe_extract_archive(
        archive, Path(EXTRACT_DIR), only_dirs=True
    )
    logger.info("Extracted to %s", extract_path)
    return extract_path


async def run_behavioral_analysis(source_dir: Path, config) -> tuple[list[dict], str]:
    """Run behavioral code analysis on extracted Python files.

    The caller validates the LLM key before invoking us so we don't ever
    return an empty list and have the wrapper mark the package as safe.

    Returns ``(findings, scan_status)``. ``scan_status`` is ``"error"``
    when the analyzer surfaced no findings *because* its alignment
    orchestrator hit infrastructure failures (e.g. the LLM was
    unreachable) — otherwise a degraded scan would masquerade as
    ``is_safe=True``. See ``analysis_scan_status`` for the exact rule.
    """
    from mcpscanner.core.analyzers.behavioral.code_analyzer import (
        BehavioralCodeAnalyzer,
    )
    from mcpscanner.core.pypi_scanner import analysis_scan_status

    analyzer = BehavioralCodeAnalyzer(config)
    logger.info("Running behavioral analysis on %s", source_dir)
    results = await analyzer.analyze(str(source_dir), {})

    findings = []
    for finding in results:
        findings.append({
            "analyzer": "behavioral",
            "severity": finding.severity,
            "threat_category": finding.threat_category,
            "summary": finding.summary,
            "details": finding.details if finding.details else {},
        })
    logger.info("Behavioral analysis: %d findings", len(findings))
    return findings, analysis_scan_status(analyzer, findings)


async def main():
    real_stdout = sys.stdout
    sys.stdout = sys.stderr

    parser = argparse.ArgumentParser(description="PyPI package scanner")
    parser.add_argument("package", help="PyPI package name")
    parser.add_argument("--version", help="Package version")
    args = parser.parse_args()

    try:
        from mcpscanner.config.config import Config
        from mcpscanner.core.package_sandbox import count_source_files
        from mcpscanner.core.pypi_scanner import LLMNotConfiguredError

        llm_key = os.environ.get("LLM_API_KEY", "")
        if not llm_key:
            # Refuse to declare is_safe=True for an un-analysed package.
            raise LLMNotConfiguredError(
                "LLM_API_KEY not provided to the container; refusing to "
                "report is_safe=True for an un-analysed package"
            )

        config = Config(
            llm_provider_api_key=llm_key,
            llm_model=os.environ.get("LLM_MODEL", "gpt-4o-mini"),
            llm_base_url=os.environ.get("LLM_BASE_URL", ""),
            llm_api_version=os.environ.get("LLM_API_VERSION", ""),
        )

        archive = download_package(args.package, args.version)
        source_dir = extract_package(archive)

        behavioral_findings, scan_status = await run_behavioral_analysis(
            source_dir, config
        )

        # Shared counter so SDK and Docker emit the same value for the
        # same package tree.
        py_files = count_source_files(
            source_dir, extensions=(".py",), skip_dirs=()
        )

        # A degraded scan (LLM unreachable, etc.) reports no findings but
        # must not claim the package is safe.
        is_safe = len(behavioral_findings) == 0 if scan_status == "completed" else None

        output = {
            "package": args.package,
            "version": args.version or "latest",
            "source_dir": str(source_dir),
            "python_files_scanned": py_files,
            "total_findings": len(behavioral_findings),
            "behavioral_findings": len(behavioral_findings),
            "is_safe": is_safe,
            "scan_status": scan_status,
            "findings": behavioral_findings,
        }

        real_stdout.write(json.dumps(output) + "\n")

    except Exception as e:
        error_output = {
            "package": args.package,
            "version": args.version or "latest",
            "error": str(e),
            "error_code": _classify_error(e),
            "is_safe": None,
            "scan_status": "error",
            "findings": [],
        }
        real_stdout.write(json.dumps(error_output) + "\n")
        sys.exit(1)


def _classify_error(exc: BaseException) -> str:
    """Thin wrapper around :func:`mcpscanner.core.package_sandbox.classify_exception`.

    Single-sourcing the vocabulary in ``package_sandbox`` keeps the
    documented ``error_code`` strings (see ``docs/pypi-scanning.md``)
    aligned with both Docker entrypoints. The wrapper is kept so legacy
    references inside this file don't break, and so the lazy
    ``mcpscanner.core`` import keeps happening inside ``main`` rather
    than at module load.
    """
    try:
        from mcpscanner.core.package_sandbox import classify_exception
    except Exception:  # noqa: BLE001 - never let classifier mask the real error
        return "scan_failed"
    return classify_exception(exc)


if __name__ == "__main__":
    asyncio.run(main())
