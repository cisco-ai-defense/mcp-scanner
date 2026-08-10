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
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ..config.constants import MCPScannerConstants
from ..utils.log_format import sanitize_log_value
from .analyzers.base import SecurityFinding
from .analyzers.yara_analyzer import YaraAnalyzer

# Traversal lives in its own dependency-light module on purpose: importing the
# behavioural analyzer would pull in ``litellm`` (~11s, ~880 modules), which
# would defeat the point of a no-LLM scan path.
from .source_discovery import find_source_files

logger = logging.getLogger(__name__)

# Severity for a file we failed to examine. ``UNKNOWN`` is the codebase's
# existing "analyzer didn't run" value (see ``result.get_highest_severity``),
# so error rows sort and render through every formatter unchanged. A bespoke
# ``ERROR`` severity would be dropped by ``--format by_severity``, which only
# iterates the known ordering.
_NOT_EXAMINED = "UNKNOWN"

_SEVERITY_RANK = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 1, "SAFE": 0, "UNKNOWN": 0}


def _read_source_text(path: str) -> Tuple[Optional[str], Optional[str]]:
    """Read ``path`` as text.

    Returns ``(text, error)`` where exactly one side is set, or ``(None,
    None)`` for a deliberate skip:

    * ``(text, None)`` — read succeeded.
    * ``(None, None)`` — file exceeds the size ceiling, skipped on purpose.
    * ``(None, message)`` — read failed; the caller must surface this rather
      than omit the file, or an unreadable tree would report as clean.

    Undecodable bytes are replaced rather than raising, because YARA rules are
    still useful against partially binary content.
    """
    try:
        if os.path.getsize(path) > MCPScannerConstants.MAX_FILE_SIZE_BYTES * 5:
            logger.debug("source scan skipping huge file: %s", sanitize_log_value(path))
            return None, None
        with open(path, "rb") as handle:
            return handle.read().decode("utf-8", errors="replace"), None
    except OSError as exc:
        # ``exc`` embeds the offending filename, which is attacker-controlled
        # for a scanned tree; sanitizing keeps a crafted name from forging
        # fields in the structured ``key=value`` log line.
        logger.warning(
            "source scan could not read %s: %s",
            sanitize_log_value(path),
            sanitize_log_value(exc),
        )
        return None, str(exc)


def _row(
    display_name: str,
    source_file: str,
    *,
    severity: str,
    summary: str,
    threat_names: Sequence[str] = (),
    total_findings: int = 0,
    status: str = "completed",
) -> Dict[str, Any]:
    """Build one report-generator-compatible result row for a scanned file.

    The shape mirrors the rows produced for behavioral scans so the existing
    ``--format`` renderers and ``--analyzer-filter`` grouping work unchanged.
    Findings are keyed under ``yara_analyzer`` to match the analyzer name the
    report generator filters on. ``is_safe`` is derived from ``severity`` so a
    file we failed to examine can never be reported as clean.
    """
    return {
        "tool_name": display_name,
        "tool_description": f"Source file {display_name}",
        "status": status,
        "is_safe": severity == "SAFE",
        "findings": {
            "yara_analyzer": {
                "severity": severity,
                "threat_summary": summary,
                "threat_names": list(threat_names),
                "total_findings": total_findings,
                "source_file": source_file,
            }
        },
    }


def _match_row(
    display_name: str, source_file: str, findings: List[SecurityFinding]
) -> Dict[str, Any]:
    """Build the row for a file whose scan completed, matches or not."""
    if not findings:
        return _row(
            display_name,
            source_file,
            severity="SAFE",
            summary="No YARA rule matches detected",
        )

    return _row(
        display_name,
        source_file,
        severity=max(
            (f.severity for f in findings), key=lambda s: _SEVERITY_RANK.get(s, 0)
        ),
        summary=findings[0].summary,
        threat_names=sorted({f.threat_category for f in findings if f.threat_category}),
        total_findings=len(findings),
    )


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
        ``True``) so the output enumerates everything that was examined rather
        than only what matched. A file that could not be read, or whose YARA
        scan raised, is reported ``status="error"`` with severity ``UNKNOWN``
        rather than being dropped or misreported as clean.

    Raises:
        FileNotFoundError: If ``source_path`` does not exist.
    """
    if not os.path.exists(source_path):
        raise FileNotFoundError(f"Source path not found: {source_path}")

    analyzer = YaraAnalyzer(rules_dir=rules_dir)
    is_dir = os.path.isdir(source_path)
    source_files = (
        await asyncio.to_thread(find_source_files, source_path)
        if is_dir
        else [source_path]
    )

    logger.info(
        "yara source scan start target=%s files=%d",
        sanitize_log_value(source_path),
        len(source_files),
    )

    results: List[Dict[str, Any]] = []
    for source_file in source_files:
        display_name = (
            os.path.relpath(source_file, source_path)
            if is_dir
            else os.path.basename(source_file)
        )

        source_text, read_error = await asyncio.to_thread(
            _read_source_text, source_file
        )
        if read_error is not None:
            results.append(
                _row(
                    display_name,
                    source_file,
                    severity=_NOT_EXAMINED,
                    summary=f"Source file could not be read: {read_error}",
                    status="error",
                )
            )
            continue
        if source_text is None:  # oversized: skipped deliberately
            continue

        try:
            findings = await analyzer.analyze(
                source_text,
                context={"tool_name": display_name, "content_type": "source_code"},
            )
        except Exception as exc:
            # Failure to gather evidence must not look like evidence of
            # compliance, so the file is surfaced instead of dropped. The
            # exception text is sanitized because it can carry rule or file
            # names from the scanned tree.
            logger.error(
                "YARA scan failed for %s: %s",
                sanitize_log_value(source_file),
                sanitize_log_value(exc),
            )
            results.append(
                _row(
                    display_name,
                    source_file,
                    severity=_NOT_EXAMINED,
                    summary=f"YARA scan failed: {exc}",
                    status="error",
                )
            )
            continue

        results.append(_match_row(display_name, source_file, findings))

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

    flagged = sum(1 for r in results if not r.get("is_safe", True))
    logger.info(
        "yara source scan done target=%s scanned=%d flagged=%d",
        sanitize_log_value(source_path),
        len(results),
        flagged,
    )
    return results
