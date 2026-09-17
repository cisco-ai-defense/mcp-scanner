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

"""Translation of analyzer output into the CLI's result dictionaries.

The report generator consumes a per-tool dictionary shape that none of the
analyzers produce natively. These helpers do that translation, and the
THREAT/VULNERABILITY classification the non-raw output filters on.
"""

import os
from typing import Any, Dict, List, Optional

from mcpscanner.core.models import AnalyzerEnum
from mcpscanner.utils.logging_config import get_logger

from .config import _build_config

logger = get_logger(__name__)


#: Detail keys carrying the MCP threat taxonomy, and the name each takes in
#: the report payload.
_TAXONOMY_KEYS = (
    "aitech",
    "aitech_name",
    "aisubtech",
    "aisubtech_name",
    "taxonomy_description",
)


def analyzer_finding_payload(finding: Any) -> Dict[str, Any]:
    """Render one SecurityFinding into the report generator's analyzer block.

    Shared by the file-scanning commands (``virustotal``,
    ``vulnerable-package``), which report one finding per artifact rather
    than per tool.
    """
    payload: Dict[str, Any] = {
        "severity": finding.severity,
        "threat_summary": finding.summary,
        "threat_names": [finding.threat_category],
        "total_findings": 1,
        "mcp_taxonomies": [],
    }
    if finding.details:
        taxonomy = {
            key.replace("taxonomy_description", "description"): finding.details[key]
            for key in _TAXONOMY_KEYS
            if key in finding.details
        }
        if taxonomy:
            payload["mcp_taxonomies"].append(taxonomy)
    return payload


def _package_scan_to_tool_results(
    *,
    scan_results: dict,
    pkg_spec: str,
    ecosystem_label: str,
) -> list:
    """Render a package scanner JSON payload into the per-tool result shape
    the report generator consumes. Shared between the ``pypi-scan`` and
    ``npm-scan`` CLI handlers so the two flows stay aligned."""
    scan_status = scan_results.get("scan_status", "completed")
    is_safe = scan_results.get("is_safe")

    if scan_status == "error" or is_safe is None:
        message = scan_results.get("error") or (
            f"{ecosystem_label} package scan of {pkg_spec} could not be completed"
        )
        return [
            {
                "tool_name": pkg_spec,
                "tool_description": message,
                "status": "error",
                "is_safe": None,
                "findings": {},
            }
        ]

    out: list = []
    for finding in scan_results.get("findings", []):
        analyzer_name = (finding.get("analyzer", "unknown") or "unknown") + "_analyzer"
        out.append(
            {
                "tool_name": (
                    (finding.get("details") or {}).get("function_name", pkg_spec)
                ),
                "tool_description": finding.get("summary", ""),
                "status": "completed",
                "is_safe": False,
                "findings": {
                    analyzer_name: {
                        "severity": finding.get("severity", "UNKNOWN"),
                        "threat_summary": finding.get("summary", ""),
                        "threat_names": [finding.get("threat_category", "UNKNOWN")],
                        "total_findings": 1,
                        "mcp_taxonomies": [],
                    }
                },
            }
        )
    if not out:
        out.append(
            {
                "tool_name": pkg_spec,
                "tool_description": f"{ecosystem_label} package scan of {pkg_spec}",
                "status": "completed",
                "is_safe": True,
                "findings": {},
            }
        )
    return out


def _finding_threat_vuln_classification(finding: Any) -> Optional[str]:
    """Per-finding THREAT/VULNERABILITY label used for CLI output filtering."""
    details = finding.details or {}
    classification = details.get("threat_vulnerability_classification")
    if classification:
        return str(classification).upper()
    if getattr(finding, "severity", "") in {"HIGH", "MEDIUM", "LOW"} and getattr(
        finding, "threat_category", ""
    ):
        return "THREAT"
    return None


def _behavioral_findings_for_cli(func_findings: List[Any]) -> List[Any]:
    """When a tool has both THREAT and VULNERABILITY rows, keep THREAT rows only."""
    threat_rows = [
        f for f in func_findings if _finding_threat_vuln_classification(f) == "THREAT"
    ]
    if threat_rows:
        return threat_rows
    return func_findings


def _infer_behavioral_threat_classification(
    func_findings: List[Any], max_severity: str
) -> Optional[str]:
    """Return THREAT/VULNERABILITY classification for CLI filtering.

    When a tool has multiple findings, prefer ``THREAT`` if any row is
    classified as a threat so VULNERABILITY rows do not hide real threats
    in the non-raw CLI filter.
    """
    cli_findings = _behavioral_findings_for_cli(func_findings)
    classifications: List[str] = []
    for finding in cli_findings:
        classification = _finding_threat_vuln_classification(finding)
        if classification:
            classifications.append(classification)

    if any(c == "THREAT" for c in classifications):
        return "THREAT"
    if classifications:
        return classifications[0]

    if max_severity in {"HIGH", "MEDIUM", "LOW"} and any(
        getattr(f, "threat_category", "") for f in cli_findings
    ):
        return "THREAT"
    return None


def _build_behavioral_results(
    analyzer: Any,
    findings: List[Any],
    source_path: str,
) -> List[Dict[str, Any]]:
    """Build tool-style result dicts for every function analyzed by the behavioral analyzer.

    ``analyze()`` returns one ``SecurityFinding`` per scanned MCP tool (including
    SAFE rows). Findings are the authoritative enumeration; ``analyzed_functions``
    is merged in when present so legacy side-channel data still surfaces tools
    that somehow lack a finding row.
    """
    findings_by_key: Dict[tuple, List[Any]] = {}
    for finding in findings:
        details = finding.details or {}
        func_name = details.get("function_name", "unknown")
        src_file = details.get("source_file", source_path)
        findings_by_key.setdefault((src_file, func_name), []).append(finding)

    severity_order = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "SAFE": 0, "UNKNOWN": 0}
    results: List[Dict[str, Any]] = []

    analyzed_functions = getattr(analyzer, "analyzed_functions", []) or []
    tool_keys: List[tuple] = []
    seen_keys: set = set()
    for key in findings_by_key:
        if key not in seen_keys:
            tool_keys.append(key)
            seen_keys.add(key)
    for analyzed in analyzed_functions:
        func_name = analyzed.get("name", "unknown")
        source_file = analyzed.get("source_file", source_path)
        key = (source_file, func_name)
        if key not in seen_keys:
            tool_keys.append(key)
            seen_keys.add(key)

    for source_file, func_name in tool_keys:
        display_name = (
            os.path.basename(source_file)
            if source_file and source_file != source_path
            else source_path
        )
        func_findings = findings_by_key.get((source_file, func_name), [])

        if func_findings:
            cli_findings = _behavioral_findings_for_cli(func_findings)
            max_severity = max(
                (f.severity for f in cli_findings),
                key=lambda s: severity_order.get(s, 0),
            )

            mcp_taxonomies: List[Dict[str, Any]] = []
            for finding in cli_findings:
                taxonomy = getattr(finding, "mcp_taxonomy", None)
                if not taxonomy:
                    continue
                taxonomy_key = (
                    taxonomy.get("aitech"),
                    taxonomy.get("aisubtech"),
                )
                existing_keys = [
                    (t.get("aitech"), t.get("aisubtech")) for t in mcp_taxonomies
                ]
                if taxonomy_key not in existing_keys:
                    mcp_taxonomies.append(taxonomy)

            threat_vuln_classification = _infer_behavioral_threat_classification(
                func_findings, max_severity
            )

            # Derive is_safe from severity instead of hardcoding False.
            # Analyzers can now emit SAFE-severity findings for tools that
            # came back clean (see BehavioralCodeAnalyzer.analyze docstring);
            # those rows must NOT be filtered out downstream as unsafe.
            is_safe_row = max_severity == "SAFE"

            analyzer_finding: Dict[str, Any] = {
                "severity": max_severity,
                "threat_summary": cli_findings[0].summary,
                "threat_names": sorted(
                    {f.threat_category for f in cli_findings if f.threat_category}
                ),
                "total_findings": len(cli_findings),
                "source_file": source_file,
                "mcp_taxonomies": mcp_taxonomies,
            }
            if threat_vuln_classification:
                analyzer_finding["threat_vulnerability_classification"] = (
                    threat_vuln_classification
                )

            results.append(
                {
                    "tool_name": func_name,
                    "tool_description": f"MCP function from {display_name}",
                    "status": "completed",
                    "is_safe": is_safe_row,
                    "findings": {"behavioral_analyzer": analyzer_finding},
                }
            )
        else:
            results.append(
                {
                    "tool_name": func_name,
                    "tool_description": f"MCP function from {display_name}",
                    "status": "completed",
                    "is_safe": True,
                    "findings": {
                        "behavioral_analyzer": {
                            "severity": "SAFE",
                            "threat_summary": "No behavioral mismatches detected",
                            "threat_names": [],
                            "total_findings": 0,
                            "source_file": source_file,
                            "mcp_taxonomies": [],
                        }
                    },
                }
            )

    if not results:
        results.append(
            {
                "tool_name": "No MCP functions found",
                "tool_description": f"No @mcp.tool() decorators found in {source_path}",
                "status": "completed",
                "is_safe": True,
                "findings": {},
            }
        )

    return results


async def _run_behavioral_analyzer_on_source(source_path: str) -> List[Dict[str, Any]]:
    """Run behavioral analyzer on source code and format results.

    Args:
        source_path: Path to Python file or directory to analyze

    Returns:
        List of formatted result dictionaries containing every MCP tool the
        analyzer visited, regardless of whether it produced a finding. Tools
        with no behavioral mismatch are included with ``is_safe=True``.
    """
    from mcpscanner.core.analyzers.behavioral import BehavioralCodeAnalyzer

    cfg = _build_config([AnalyzerEnum.BEHAVIORAL])
    analyzer = BehavioralCodeAnalyzer(cfg)

    findings = await analyzer.analyze(source_path, context={"file_path": source_path})

    return _build_behavioral_results(analyzer, findings, source_path)
