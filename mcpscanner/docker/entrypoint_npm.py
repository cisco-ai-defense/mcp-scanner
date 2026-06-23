#!/usr/bin/env python3
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
"""Entrypoint for the npm-scanner Docker image.

Downloads a tarball from the npm registry, extracts it under
``/tmp/package`` using the safe-extraction primitives shared with the SDK
local path, and runs the JS/TS behavioural analyzer over the extracted
sources. The package's own code is never executed.

Final results land on real stdout as a single JSON line; everything else
(progress, warnings, analyzer logs) goes to stderr.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
from pathlib import Path
from urllib.parse import urlparse

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s: %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("npm-scanner")


DOWNLOAD_DIR = Path("/work/download")
EXTRACT_DIR = Path("/work/package")


async def run_behavioral_analysis(source_dir: Path, config) -> tuple[list[dict], str]:
    """Run JS/TS behavioural analysis on every supported file under
    ``source_dir``. Findings are serialised to the same dict shape the
    PyPI entrypoint emits so downstream consumers can share code paths.

    The caller validates the LLM key before invoking us; if it's missing
    we now raise instead of silently returning zero findings (which used
    to surface to callers as ``is_safe: True`` for a package the scanner
    never actually analysed).

    Returns ``(findings, scan_status)``. ``scan_status`` is ``"error"``
    when the analyzer surfaced no findings *because* its alignment
    orchestrator hit infrastructure failures (e.g. the LLM was
    unreachable), so a degraded scan can't masquerade as ``is_safe=True``.
    """
    from mcpscanner.core.analyzers.behavioral.js_code_analyzer import (
        JSBehavioralCodeAnalyzer,
    )
    from mcpscanner.core.pypi_scanner import analysis_scan_status

    analyzer = JSBehavioralCodeAnalyzer(config)
    logger.info("Running JS behavioural analysis on %s", source_dir)

    findings = []
    results = await analyzer.analyze(str(source_dir), {})
    for f in results:
        findings.append(
            {
                "analyzer": "behavioral",
                "severity": f.severity,
                "threat_category": f.threat_category,
                "summary": f.summary,
                "details": f.details if f.details else {},
            }
        )
    logger.info("Behavioural analysis: %d findings", len(findings))
    return findings, analysis_scan_status(analyzer, findings)


async def main() -> None:
    real_stdout = sys.stdout
    sys.stdout = sys.stderr

    parser = argparse.ArgumentParser(description="npm package scanner (Docker)")
    parser.add_argument("package", help="npm package name (supports @scope/name)")
    parser.add_argument("--version", help="package version (default: latest)")
    args = parser.parse_args()

    try:
        from mcpscanner.config.config import Config
        from mcpscanner.config.constants import MCPScannerConstants as CONSTANTS
        from mcpscanner.core.analyzers.behavioral.js_code_analyzer import (
            _JS_EXTENSIONS,
            _SKIP_DIRS,
        )
        from mcpscanner.core.package_sandbox import (
            count_source_files,
            download_archive,
            safe_extract_archive,
        )
        from mcpscanner.core.pypi_scanner import (
            LLMNotConfiguredError,
            _https_get_json,
        )

        llm_key = os.environ.get("LLM_API_KEY", "")
        if not llm_key:
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

        registry = os.environ.get("NPM_REGISTRY_URL", CONSTANTS.NPM_REGISTRY_URL).rstrip("/")
        encoded = (
            args.package.replace("/", "%2F")
            if args.package.startswith("@")
            else args.package
        )
        meta_url = (
            f"{registry}/{encoded}/{args.version}"
            if args.version
            else f"{registry}/{encoded}/latest"
        )

        logger.info("Fetching npm manifest: %s", meta_url)
        registry_host = urlparse(registry).hostname
        manifest = _https_get_json(
            meta_url,
            user_agent="mcp-scanner/npm-docker",
            timeout=CONSTANTS.PACKAGE_DOWNLOAD_TIMEOUT,
            allowed_hosts=(registry_host,) if registry_host else None,
        )

        resolved_version = manifest.get("version") or args.version or "unknown"
        dist = manifest.get("dist") or {}
        tarball = dist.get("tarball")
        if not tarball:
            raise RuntimeError(
                f"no tarball URL for {args.package}@{resolved_version}"
            )
        integrity = dist.get("integrity")
        shasum = dist.get("shasum")
        if integrity:
            expected_digest, digest_algo = integrity, None
        elif shasum:
            expected_digest, digest_algo = shasum, "sha1"
        else:
            expected_digest, digest_algo = None, None

        # Pin the tarball fetch to hosts under the configured registry's
        # apex domain so a compromised manifest cannot redirect us to an
        # attacker-controlled HTTPS host even though Docker isolation
        # would already contain the blast radius. Mirrors the SDK path.
        # ``registry_host`` was resolved above for the manifest fetch.
        allowed_hosts: tuple[str, ...] = ()
        if registry_host:
            allowed_hosts = (registry_host,)
            if registry_host.endswith("npmjs.org"):
                allowed_hosts = allowed_hosts + ("npmjs.com", "npmjs.org")

        DOWNLOAD_DIR.mkdir(parents=True, exist_ok=True)
        EXTRACT_DIR.mkdir(parents=True, exist_ok=True)

        archive = download_archive(
            tarball,
            DOWNLOAD_DIR,
            expected_digest=expected_digest,
            expected_digest_algo=digest_algo,
            allowed_hosts=allowed_hosts or None,
        )
        source_root = safe_extract_archive(archive, EXTRACT_DIR)

        findings, scan_status = await run_behavioral_analysis(source_root, config)
        js_files = count_source_files(
            source_root, extensions=_JS_EXTENSIONS, skip_dirs=_SKIP_DIRS
        )

        # A degraded scan (LLM unreachable, etc.) reports no findings but
        # must not claim the package is safe.
        is_safe = len(findings) == 0 if scan_status == "completed" else None

        output = {
            "ecosystem": "npm",
            "package": args.package,
            "version": resolved_version,
            "source_dir": str(source_root),
            "files_scanned": js_files,
            "js_files_scanned": js_files,
            "total_findings": len(findings),
            "behavioral_findings": len(findings),
            "is_safe": is_safe,
            "scan_status": scan_status,
            "findings": findings,
        }
        real_stdout.write(json.dumps(output) + "\n")

    except Exception as e:
        # Surface a stable error code so the host scanner can re-raise
        # config-class errors (LLM key missing) as their typed exception
        # rather than wrapping every container failure into NPMScanError.
        error_code = _classify_error(e)
        error_output = {
            "ecosystem": "npm",
            "package": args.package,
            "version": args.version or "latest",
            "error": str(e),
            "error_code": error_code,
            "is_safe": None,
            "scan_status": "error",
            "findings": [],
        }
        real_stdout.write(json.dumps(error_output) + "\n")
        sys.exit(1)


def _classify_error(exc: BaseException) -> str:
    """Thin wrapper around :func:`mcpscanner.core.package_sandbox.classify_exception`.

    The host side branches on the documented ``error_code`` strings, so
    we route both entrypoints through one helper to prevent drift. The
    lazy import keeps an unimportable ``mcpscanner.core`` from
    suppressing the structured JSON error envelope.
    """
    try:
        from mcpscanner.core.package_sandbox import classify_exception
    except Exception:  # noqa: BLE001 - never let classifier mask the real error
        return "scan_failed"
    return classify_exception(exc)


if __name__ == "__main__":
    asyncio.run(main())
