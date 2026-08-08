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

"""No-LLM YARA scanning over raw source directories.

The ``behavioral`` scan path pairs static analysis with an LLM alignment
check, so it cannot run without LLM credentials. This module provides the
pattern-only half of that pipeline: it walks a source tree and runs the
existing YARA rules over each file's contents, with no LLM provider and no
running MCP server required.

That makes CI usable for teams that want pattern detection on a feature
branch without per-pull-request LLM spend.
"""

import asyncio
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..config.constants import MCPScannerConstants
from ..utils.log_format import sanitize_log_value
from .analyzers.base import SecurityFinding
from .analyzers.yara_analyzer import YaraAnalyzer

# Traversal lives in its own dependency-light module on purpose: importing the
# behavioural analyzer would pull in ``litellm`` (~11s, ~880 modules), which
# would defeat the point of a no-LLM scan path.
from .source_discovery import find_source_files

logger = logging.getLogger(__name__)


def _read_source_text(path: str) -> Optional[str]:
    """Read ``path`` as text, or return ``None`` if it should be skipped.

    Files larger than five times ``MAX_FILE_SIZE_BYTES`` are skipped, matching
    the behavioral prefilter's ceiling. Undecodable bytes are replaced rather
    than raising, because YARA rules are still useful against partially
    binary content.
    """
    try:
        if os.path.getsize(path) > MCPScannerConstants.MAX_FILE_SIZE_BYTES * 5:
            logger.debug("source scan skipping huge file: %s", sanitize_log_value(path))
            return None
        with open(path, "rb") as handle:
            return handle.read().decode("utf-8", errors="replace")
    except OSError as exc:
        logger.debug("source scan could not read %s: %s", sanitize_log_value(path), exc)
        return None


def _result_for_file(
    display_name: str,
    source_file: str,
    findings: List[SecurityFinding],
    status: str = "completed",
) -> Dict[str, Any]:
    """Build one report-generator-compatible result row for a scanned file.

    The shape mirrors the rows produced for behavioral scans so the existing
    ``--format`` renderers and ``--analyzer-filter`` grouping work unchanged.
    Findings are keyed under ``yara_analyzer`` to match the analyzer name the
    report generator filters on.
    """
    if not findings:
        return {
            "tool_name": display_name,
            "tool_description": f"Source file {display_name}",
            "status": status,
            "is_safe": True,
            "findings": {
                "yara_analyzer": {
                    "severity": "SAFE",
                    "threat_summary": "No YARA rule matches detected",
                    "threat_names": [],
                    "total_findings": 0,
                    "source_file": source_file,
                }
            },
        }

    severity_order = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "SAFE": 0, "UNKNOWN": 0}
    max_severity = max(
        (f.severity for f in findings),
        key=lambda s: severity_order.get(s, 0),
    )
    return {
        "tool_name": display_name,
        "tool_description": f"Source file {display_name}",
        "status": status,
        "is_safe": max_severity == "SAFE",
        "findings": {
            "yara_analyzer": {
                "severity": max_severity,
                "threat_summary": findings[0].summary,
                "threat_names": sorted(
                    {f.threat_category for f in findings if f.threat_category}
                ),
                "total_findings": len(findings),
                "source_file": source_file,
            }
        },
    }


async def scan_source_with_yara(
    source_path: str,
    *,
    rules_dir: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Run YARA rules over a source file or directory without any LLM call.

    Args:
        source_path: A source file or a directory to walk recursively.
        rules_dir: Optional custom YARA rules directory.

    Returns:
        One result row per scanned file, including clean files (``is_safe``
        ``True``) so the output enumerates everything that was examined
        rather than only what matched. A file whose YARA scan raises is
        reported with status ``error`` and severity ``ERROR`` rather than
        being silently dropped or misreported as clean.

    Raises:
        FileNotFoundError: If ``source_path`` does not exist.
    """
    if not os.path.exists(source_path):
        raise FileNotFoundError(f"Source path not found: {source_path}")

    analyzer = YaraAnalyzer(rules_dir=rules_dir)

    if os.path.isfile(source_path):
        source_files = [source_path]
    else:
        source_files = await asyncio.to_thread(find_source_files, source_path)

    logger.info(
        "yara source scan start target=%s files=%d",
        sanitize_log_value(source_path),
        len(source_files),
    )

    results: List[Dict[str, Any]] = []
    for source_file in source_files:
        display_name = (
            os.path.relpath(source_file, source_path)
            if os.path.isdir(source_path)
            else os.path.basename(source_file)
        )

        source_text = await asyncio.to_thread(_read_source_text, source_file)
        if source_text is None:
            continue

        try:
            findings = await analyzer.analyze(
                source_text,
                context={"tool_name": display_name, "content_type": "source_code"},
            )
        except Exception as exc:
            # A rule-matching failure means this file was never examined.
            # Reporting it as clean would make a gather failure
            # indistinguishable from evidence of safety, so surface it.
            logger.error(
                "YARA scan failed for %s: %s", sanitize_log_value(source_file), exc
            )
            results.append(
                {
                    "tool_name": display_name,
                    "tool_description": f"Source file {display_name}",
                    "status": "error",
                    "is_safe": False,
                    "findings": {
                        "yara_analyzer": {
                            "severity": "ERROR",
                            "threat_summary": f"YARA scan failed: {exc}",
                            "threat_names": [],
                            "total_findings": 0,
                            "source_file": source_file,
                        }
                    },
                }
            )
            continue

        results.append(_result_for_file(display_name, source_file, findings))

    if not results:
        results.append(
            {
                "tool_name": "No source files found",
                "tool_description": f"No supported source files under {source_path}",
                "status": "completed",
                "is_safe": True,
                "findings": {},
            }
        )

    matched = sum(1 for r in results if not r.get("is_safe", True))
    logger.info(
        "yara source scan done target=%s scanned=%d flagged=%d",
        sanitize_log_value(source_path),
        len(results),
        matched,
    )
    return results
