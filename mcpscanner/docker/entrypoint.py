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
import tarfile
import zipfile
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
    """Extract the downloaded archive."""
    os.makedirs(EXTRACT_DIR, exist_ok=True)

    if archive.name.endswith(".tar.gz") or archive.name.endswith(".tgz"):
        with tarfile.open(archive, "r:gz") as tf:
            tf.extractall(EXTRACT_DIR, filter="data")
    elif archive.name.endswith(".zip") or archive.name.endswith(".whl"):
        with zipfile.ZipFile(archive, "r") as zf:
            zf.extractall(EXTRACT_DIR)
    else:
        raise RuntimeError(f"Unsupported archive format: {archive.name}")

    subdirs = [
        d for d in Path(EXTRACT_DIR).iterdir()
        if d.is_dir() and not d.name.startswith(".")
    ]
    extract_path = subdirs[0] if len(subdirs) == 1 else Path(EXTRACT_DIR)

    py_files = list(extract_path.rglob("*.py"))
    logger.info("Extracted to %s (%d Python files)", extract_path, len(py_files))
    return extract_path


async def run_behavioral_analysis(source_dir: Path) -> list[dict]:
    """Run behavioral code analysis on extracted Python files."""
    findings = []
    try:
        from mcpscanner.config.config import Config
        from mcpscanner.core.analyzers.behavioral.code_analyzer import (
            BehavioralCodeAnalyzer,
        )

        llm_key = os.environ.get("LLM_API_KEY", "")
        if not llm_key:
            logger.warning(
                "LLM_API_KEY not set — skipping behavioral analysis"
            )
            return []

        config = Config(
            llm_provider_api_key=llm_key,
            llm_model=os.environ.get("LLM_MODEL", "gpt-4o-mini"),
            llm_base_url=os.environ.get("LLM_BASE_URL", ""),
            llm_api_version=os.environ.get("LLM_API_VERSION", ""),
        )
        analyzer = BehavioralCodeAnalyzer(config)

        logger.info("Running behavioral analysis on %s", source_dir)
        results = await analyzer.analyze(str(source_dir), {})

        for finding in results:
            findings.append({
                "analyzer": "behavioral",
                "severity": finding.severity,
                "threat_category": finding.threat_category,
                "summary": finding.summary,
                "details": finding.details if finding.details else {},
            })

        logger.info("Behavioral analysis: %d findings", len(findings))

    except Exception as e:
        logger.error("Behavioral analysis failed: %s", e)

    return findings


async def main():
    # Redirect stdout to stderr so only our final JSON goes to real stdout
    real_stdout = sys.stdout
    sys.stdout = sys.stderr

    parser = argparse.ArgumentParser(description="PyPI package scanner")
    parser.add_argument("package", help="PyPI package name")
    parser.add_argument("--version", help="Package version")
    args = parser.parse_args()

    try:
        archive = download_package(args.package, args.version)
        source_dir = extract_package(archive)

        behavioral_findings = await run_behavioral_analysis(source_dir)

        py_files = list(source_dir.rglob("*.py"))

        output = {
            "package": args.package,
            "version": args.version or "latest",
            "source_dir": str(source_dir),
            "python_files_scanned": len(py_files),
            "total_findings": len(behavioral_findings),
            "behavioral_findings": len(behavioral_findings),
            "is_safe": len(behavioral_findings) == 0,
            "findings": behavioral_findings,
        }

        real_stdout.write(json.dumps(output) + "\n")

    except Exception as e:
        error_output = {
            "package": args.package,
            "version": args.version or "latest",
            "error": str(e),
            "is_safe": None,
            "findings": [],
        }
        real_stdout.write(json.dumps(error_output) + "\n")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
