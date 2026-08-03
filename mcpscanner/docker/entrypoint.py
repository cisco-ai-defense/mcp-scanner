#!/usr/bin/env python3
"""
Entrypoint script for the MCP Scanner PyPI Docker container.

Downloads a PyPI package archive without executing it, extracts the
sources safely, and runs behavioural analysis. Final results are printed
as JSON to stdout; logs go to stderr.
"""

import argparse
import asyncio
import json
import logging
import os
import sys
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s: %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("pypi-scanner")

DOWNLOAD_DIR = Path("/work/download")
EXTRACT_DIR = Path("/work/package")


def download_package(package: str, version: str | None) -> tuple[Path, str]:
    """Download a PyPI sdist or wheel without executing package code."""
    from mcpscanner.config.constants import MCPScannerConstants as CONSTANTS
    from mcpscanner.core.package_sandbox import (
        download_archive,
        pypi_tarball_allowed_hosts,
        validate_pypi_package_name,
    )
    from mcpscanner.core.pypi_scanner import resolve_pypi_archive_url

    validate_pypi_package_name(package)
    DOWNLOAD_DIR.mkdir(parents=True, exist_ok=True)

    spec = f"{package}=={version}" if version else package
    logger.info("Downloading %s", spec)

    url, resolved_version, expected_digest = resolve_pypi_archive_url(
        package, version
    )
    archive = download_archive(
        url,
        DOWNLOAD_DIR,
        expected_digest=expected_digest,
        expected_digest_algo="sha256" if expected_digest else None,
        allowed_hosts=pypi_tarball_allowed_hosts(CONSTANTS.PYPI_INDEX_URL),
    )

    logger.info("Downloaded: %s", archive.name)
    return archive, resolved_version


def extract_package(archive: Path) -> Path:
    """Extract the downloaded archive using the shared safe-extraction
    helpers so the byte / file-count caps and traversal protections are
    applied here too.

    ``only_dirs=True`` preserves the historical PyPI Docker behaviour of
    selecting the single ``<name>-<version>/`` extraction subdir even
    when sibling files (``README``, ``LICENSE``, ``setup.cfg``) land at
    the extraction root.
    """
    from mcpscanner.core.package_sandbox import safe_extract_archive

    EXTRACT_DIR.mkdir(parents=True, exist_ok=True)
    extract_path = safe_extract_archive(
        archive, EXTRACT_DIR, only_dirs=True
    )
    logger.info("Extracted to %s", extract_path)
    return extract_path


async def run_behavioral_analysis(source_dir: Path, config) -> tuple[list[dict], str]:
    """Run behavioral code analysis on extracted Python files."""
    from mcpscanner.core.analyzers.behavioral.code_analyzer import (
        BehavioralCodeAnalyzer,
    )
    from mcpscanner.core.pypi_scanner import (
        _reportable_findings,
        analysis_scan_status,
    )

    analyzer = BehavioralCodeAnalyzer(config)
    logger.info("Running behavioral analysis on %s", source_dir)
    results = await analyzer.analyze(str(source_dir), {})

    findings = []
    for finding in _reportable_findings(results):
        findings.append({
            "analyzer": "behavioral",
            "severity": finding.severity,
            "threat_category": finding.threat_category,
            "summary": finding.summary,
            "details": finding.details if finding.details else {},
        })
    logger.info("Behavioral analysis: %d findings", len(findings))
    return findings, analysis_scan_status(analyzer, results)


async def main():
    real_stdout = sys.stdout
    sys.stdout = sys.stderr

    parser = argparse.ArgumentParser(description="PyPI package scanner")
    parser.add_argument("package", help="PyPI package name")
    parser.add_argument("--version", help="Package version")
    args = parser.parse_args()

    resolved_version = args.version or "latest"

    try:
        from mcpscanner.config.config import Config
        from mcpscanner.config.constants import MCPScannerConstants as CONSTANTS
        from mcpscanner.core.package_sandbox import count_source_files
        from mcpscanner.core.pypi_scanner import LLMNotConfiguredError

        llm_key = os.environ.get("LLM_API_KEY", "")
        if not llm_key:
            raise LLMNotConfiguredError(
                "LLM_API_KEY not provided to the container; refusing to "
                "report is_safe=True for an un-analysed package"
            )

        # Keep the LLM key out of the environment while downloading and
        # extracting so a hostile archive cannot read it from os.environ.
        saved_llm_key = os.environ.pop("LLM_API_KEY", None)
        try:
            archive, resolved_version = download_package(args.package, args.version)
            source_dir = extract_package(archive)
        finally:
            if saved_llm_key is not None:
                os.environ["LLM_API_KEY"] = saved_llm_key

        config = Config(
            llm_provider_api_key=llm_key,
            llm_model=os.environ.get("LLM_MODEL", CONSTANTS.DEFAULT_LLM_MODEL),
            llm_base_url=os.environ.get("LLM_BASE_URL", ""),
            llm_api_version=os.environ.get("LLM_API_VERSION", ""),
        )

        behavioral_findings, scan_status = await run_behavioral_analysis(
            source_dir, config
        )

        py_files = count_source_files(
            source_dir,
            extensions=(".py",),
            skip_dirs=("__pycache__", "node_modules"),
        )

        is_safe = len(behavioral_findings) == 0 if scan_status == "completed" else None

        output = {
            "package": args.package,
            "version": resolved_version,
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
            "version": resolved_version,
            "error": str(e),
            "error_code": _classify_error(e),
            "is_safe": None,
            "scan_status": "error",
            "findings": [],
        }
        real_stdout.write(json.dumps(error_output) + "\n")
        sys.exit(1)


def _classify_error(exc: BaseException) -> str:
    """Map exceptions to stable ``error_code`` tokens for host consumers."""
    try:
        from mcpscanner.core.package_sandbox import classify_exception
    except Exception:  # noqa: BLE001 - never let classifier mask the real error
        return "scan_failed"
    return classify_exception(exc)


if __name__ == "__main__":
    asyncio.run(main())
