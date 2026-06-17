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

"""Result module for MCP Scanner SDK.

This module provides classes and utilities for handling scan results.
"""

import json
from typing import Any, Dict, List, Optional, Union

from .analyzers.base import SecurityFinding
from .analyzers.meta_analyzer import build_meta_audit_payload


class ScanResult:
    """Base class for all scan results.

    Attributes:
        status (str): The status of the scan (e.g., "completed", "failed", "skipped").
        analyzers (List[str]): List of analyzers used.
        findings (List[SecurityFinding]): The security findings found during the scan.
        server_source (str): The source server/config for this result.
        server_name (str): The name of the server from config.
        meta_filtered_findings (List[SecurityFinding]): Findings the meta-analyzer
            judged to be false positives and removed from ``findings``. Each
            finding carries audit fields (``meta_false_positive=True``,
            ``meta_reason``, optional ``meta_confidence``) in its ``details``.
            Empty when meta-analysis did not run or did not drop anything;
            non-empty here is the only signal an operator has that meta
            filtering changed the scan output.
    """

    def __init__(
        self,
        status: str,
        analyzers: List[str],
        findings: List[SecurityFinding],
        server_source: str = None,
        server_name: str = None,
    ):
        """Initialize a new ScanResult instance.

        Args:
            status (str): The status of the scan.
            analyzers (List[str]): List of analyzers used.
            findings (List[SecurityFinding]): The security findings found during the scan.
            server_source (str): The source server/config for this result.
            server_name (str): The name of the server from config.
        """
        self.status = status
        self.analyzers = analyzers
        self.findings = findings
        self.server_source = server_source
        self.server_name = server_name
        # Set by ``Scanner._run_meta_analysis_on_*`` after meta filtering.
        # Default empty so every result has the attribute and downstream
        # serializers don't need ``getattr(..., default=[])`` everywhere.
        self.meta_filtered_findings: List[SecurityFinding] = []

    @property
    def is_safe(self) -> bool:
        """Check if the scan result indicates the item is safe.

        Returns:
            bool: True if no security findings were found, False otherwise.
        """
        return len(self.findings) == 0

    def __str__(self) -> str:
        """Return a string representation of the scan result."""
        return f"ScanResult(status={self.status}, findings={len(self.findings)})"


class ToolScanResult(ScanResult):
    """Aggregates all findings from a tool scan.

    Inherits all attributes from ScanResult and adds:
        tool_name (str): The name of the scanned tool.
        tool_description (str): The description of the scanned tool.
    """

    def __init__(
        self,
        tool_name: str,
        tool_description: str,
        status: str,
        analyzers: List[str],
        findings: List[SecurityFinding],
        server_source: str = None,
        server_name: str = None,
    ):
        """Initialize a new ToolScanResult instance.

        Args:
            tool_name (str): The name of the scanned tool.
            tool_description (str): The description of the scanned tool.
            status (str): Inherited - The status of the scan.
            analyzers (List[str]): Inherited - List of analyzers used.
            findings (List[SecurityFinding]): Inherited - The security findings.
            server_source (str): Inherited - The source server/config.
            server_name (str): Inherited - The name of the server from config.
        """
        self.tool_name = tool_name
        self.tool_description = tool_description
        super().__init__(status, analyzers, findings, server_source, server_name)

    def __str__(self) -> str:
        """Return a string representation of the tool scan result."""
        return f"ToolScanResult(tool_name={self.tool_name}, status={self.status}, findings={len(self.findings)})"


class PromptScanResult(ScanResult):
    """Aggregates all findings from a prompt scan.

    Inherits all attributes from ScanResult and adds:
        prompt_name (str): The name of the scanned prompt.
        prompt_description (str): The description of the scanned prompt.
    """

    def __init__(
        self,
        prompt_name: str,
        prompt_description: str,
        status: str,
        analyzers: List[str],
        findings: List[SecurityFinding],
        server_source: str = None,
        server_name: str = None,
    ):
        """Initialize a new PromptScanResult instance.

        Args:
            prompt_name (str): The name of the scanned prompt.
            prompt_description (str): The description of the scanned prompt.
            status (str): Inherited - The status of the scan.
            analyzers (List[str]): Inherited - List of analyzers used.
            findings (List[SecurityFinding]): Inherited - The security findings.
            server_source (str): Inherited - The source server/config.
            server_name (str): Inherited - The name of the server from config.
        """
        self.prompt_name = prompt_name
        self.prompt_description = prompt_description
        super().__init__(status, analyzers, findings, server_source, server_name)

    def __str__(self) -> str:
        """Return a string representation of the prompt scan result."""
        return f"PromptScanResult(prompt_name={self.prompt_name}, status={self.status}, findings={len(self.findings)})"


class ResourceScanResult(ScanResult):
    """Aggregates all findings from a resource scan.

    Inherits all attributes from ScanResult and adds:
        resource_uri (str): The URI of the scanned resource.
        resource_name (str): The name of the scanned resource.
        resource_mime_type (str): The MIME type of the resource.
        resource_description (str): The MCP-advertised description of the
            resource (defaults to ``""`` if absent — never ``None``).
            Mirrors the way prompt and tool scan results carry
            ``prompt_description`` / ``tool_description``.
        resource_text (str): The text content the primary analyzers
            actually consumed (defaults to ``""``). Retained on the
            result so downstream consumers (meta-analyzer, diagnostics)
            can second-guess findings against the same evidence the
            analyzers saw. The artifact serializers do not include this
            field, so retention does not bloat JSON / Markdown reports
            or API responses.
    """

    def __init__(
        self,
        resource_uri: str,
        resource_name: str,
        resource_mime_type: str,
        status: str,
        analyzers: List[str],
        findings: List[SecurityFinding],
        server_source: str = None,
        server_name: str = None,
        resource_description: Optional[str] = None,
        resource_text: Optional[str] = None,
    ):
        """Initialize a new ResourceScanResult instance.

        Args:
            resource_uri (str): The URI of the scanned resource.
            resource_name (str): The name of the scanned resource.
            resource_mime_type (str): The MIME type of the resource.
            status (str): Inherited - The status of the scan.
            analyzers (List[str]): Inherited - List of analyzers used.
            findings (List[SecurityFinding]): Inherited - The security findings.
            server_source (str): Inherited - The source server/config.
            server_name (str): Inherited - The name of the server from config.
            resource_description (Optional[str]): MCP-advertised
                description. Stored as ``str`` on the instance (``None``
                input is normalised to ``""``).
            resource_text (Optional[str]): Text content the analyzers
                consumed. Stored as ``str`` on the instance (``None``
                input is normalised to ``""``).
        """
        self.resource_uri = resource_uri
        self.resource_name = resource_name
        self.resource_mime_type = resource_mime_type
        # Default to empty string (not ``None``) so consumers can rely on
        # truthiness / ``str`` operations without ``getattr(..., "") or ""``.
        self.resource_description = resource_description or ""
        self.resource_text = resource_text or ""
        super().__init__(status, analyzers, findings, server_source, server_name)

    def __str__(self) -> str:
        """Return a string representation of the resource scan result."""
        return f"ResourceScanResult(resource_uri={self.resource_uri}, mime_type={self.resource_mime_type}, status={self.status}, findings={len(self.findings)})"


class InstructionsScanResult(ScanResult):
    """Aggregates all findings from a server instructions scan.

    Inherits all attributes from ScanResult and adds:
        instructions (str): The instructions text from the server.
        server_name (str): The name of the server.
        protocol_version (str): The MCP protocol version.
    """

    def __init__(
        self,
        instructions: str,
        server_name: str,
        protocol_version: str,
        status: str,
        analyzers: List[str],
        findings: List[SecurityFinding],
        server_source: str = None,
    ):
        """Initialize a new InstructionsScanResult instance.

        Args:
            instructions (str): The instructions text from the server.
            server_name (str): The name of the server.
            protocol_version (str): The MCP protocol version.
            status (str): Inherited - The status of the scan.
            analyzers (List[str]): Inherited - List of analyzers used.
            findings (List[SecurityFinding]): Inherited - The security findings.
            server_source (str): Inherited - The source server/config.
        """
        self.instructions = instructions
        self.server_name = server_name
        self.protocol_version = protocol_version
        super().__init__(status, analyzers, findings, server_source, server_name)

    def __str__(self) -> str:
        """Return a string representation of the instructions scan result."""
        return f"InstructionsScanResult(server_name={self.server_name}, protocol_version={self.protocol_version}, status={self.status}, findings={len(self.findings)})"


def process_scan_results(
    results: List[
        Union[
            ToolScanResult, PromptScanResult, ResourceScanResult, InstructionsScanResult
        ]
    ],
) -> Dict[str, Any]:
    """Process a list of scan results and return summary statistics.

    Args:
        results: A list of scan results (tools, prompts, or resources) to process.

    Returns:
        Dict[str, Any]: A dictionary containing summary statistics about the scan results.
    """
    total_tools = len(results)
    safe_tools = [r for r in results if r.is_safe]
    unsafe_tools = [r for r in results if not r.is_safe]

    # Count findings by severity.
    #
    # L4 (intentional behaviour, documented for future reviewers):
    # ``severity_counts`` reflects ONLY findings the scan still reports
    # as live threats. ``meta_filtered_findings`` are deliberately
    # excluded from this rollup — they were judged false positives by
    # the meta-analyzer and folding them back into the totals would:
    #
    # 1. Re-inflate dashboards / SLA gates that operators built around
    #    the post-meta numbers (the very point of running the meta
    #    pass).
    # 2. Make ``unsafe_tools`` and ``severity_counts`` disagree —
    #    e.g. a tool whose ONLY findings were filtered out shows up in
    #    ``safe_tools`` (correct), but if its meta-filtered HIGH
    #    counted here, the summary would say "0 unsafe tools, 1 HIGH".
    #
    # The audit trail for filtered findings is preserved separately on
    # ``ScanResult.meta_filtered_findings`` and surfaced via the
    # ``meta_analysis`` block in CLI/SDK/API serializers (P0-2 / H3).
    # Operators who need filtered-finding totals should aggregate that
    # field directly, NOT alter this rollup.
    severity_counts = {
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
        "SAFE": 0,
        "UNKNOWN": 0,
    }
    threat_types = {}

    for result in unsafe_tools:
        for finding in result.findings:
            # Count by severity
            severity = finding.severity.upper()
            if severity in severity_counts:
                severity_counts[severity] += 1

            # Count by threat type if available
            if (
                hasattr(finding, "details")
                and finding.details
                and "threat_type" in finding.details
            ):
                threat_type = finding.details["threat_type"]
                if threat_type in threat_types:
                    threat_types[threat_type] += 1
                else:
                    threat_types[threat_type] = 1

    # L4: aggregate the filtered-finding totals as a SEPARATE, optional
    # block so callers who want them can read ``meta_filtered_counts``
    # without breaking the post-meta semantics of ``severity_counts``.
    meta_filtered_counts = {
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
        "SAFE": 0,
        "UNKNOWN": 0,
    }
    total_meta_filtered = 0
    for result in results:
        for finding in getattr(result, "meta_filtered_findings", []) or []:
            total_meta_filtered += 1
            severity = (finding.severity or "UNKNOWN").upper()
            if severity in meta_filtered_counts:
                meta_filtered_counts[severity] += 1

    return {
        "total_tools": total_tools,
        "safe_tools": len(safe_tools),
        "unsafe_tools": len(unsafe_tools),
        "severity_counts": severity_counts,
        "meta_filtered_counts": meta_filtered_counts,
        "total_meta_filtered": total_meta_filtered,
        "threat_types": threat_types,
        "results": results,
    }


def filter_results_by_severity(
    results: List[
        Union[
            ToolScanResult, PromptScanResult, ResourceScanResult, InstructionsScanResult
        ]
    ],
    severity: str,
) -> List[
    Union[ToolScanResult, PromptScanResult, ResourceScanResult, InstructionsScanResult]
]:
    """Filter scan results by severity level.

    Args:
        results: A list of scan results (tools, prompts, or resources) to filter.
        severity (str): The severity level to filter by (high, medium, low).

    Returns:
        A filtered list of scan results of the same type as input.
    """
    filtered_results = []

    for result in results:
        # If the tool has no security findings, skip it
        if result.is_safe:
            continue

        # Filter findings by severity
        filtered_findings = [
            f for f in result.findings if f.severity.lower() == severity.lower()
        ]

        # If there are findings matching the severity, include this result
        if filtered_findings:
            # Create a new result with only the filtered findings (preserve
            # type AND every state-bearing attribute).
            #
            # H2 fix: prior to this branch the reconstructed ResourceScanResult
            # silently zeroed ``resource_description`` / ``resource_text``
            # (P0-3 evidence), and EVERY result type lost
            # ``meta_filtered_findings`` (P0-2 audit trail). A pipeline of
            # ``scan → filter_results_by_severity → re-apply meta`` therefore
            # fed the meta-analyzer ``"N/A"`` for description and reported
            # ``filtered_count: 0`` for previously-dropped findings —
            # silently undoing two of the just-landed P0 fixes.
            #
            # Carry every cross-cutting attribute (server_source,
            # server_name, meta_filtered_findings) through here so the
            # filter is purely on ``findings`` and never on metadata.
            if isinstance(result, ToolScanResult):
                filtered_result = ToolScanResult(
                    tool_name=result.tool_name,
                    tool_description=result.tool_description,
                    status=result.status,
                    analyzers=result.analyzers,
                    findings=filtered_findings,
                    server_source=result.server_source,
                    server_name=result.server_name,
                )
            elif isinstance(result, PromptScanResult):
                filtered_result = PromptScanResult(
                    prompt_name=result.prompt_name,
                    prompt_description=result.prompt_description,
                    status=result.status,
                    analyzers=result.analyzers,
                    findings=filtered_findings,
                    server_source=result.server_source,
                    server_name=result.server_name,
                )
            elif isinstance(result, ResourceScanResult):
                filtered_result = ResourceScanResult(
                    resource_uri=result.resource_uri,
                    resource_name=result.resource_name,
                    resource_mime_type=result.resource_mime_type,
                    status=result.status,
                    analyzers=result.analyzers,
                    findings=filtered_findings,
                    server_source=result.server_source,
                    server_name=result.server_name,
                    resource_description=getattr(result, "resource_description", "") or "",
                    resource_text=getattr(result, "resource_text", "") or "",
                )
            elif isinstance(result, InstructionsScanResult):
                filtered_result = InstructionsScanResult(
                    instructions=result.instructions,
                    server_name=result.server_name,
                    protocol_version=result.protocol_version,
                    status=result.status,
                    analyzers=result.analyzers,
                    findings=filtered_findings,
                    server_source=result.server_source,
                )
            else:
                continue  # Skip unknown types

            # Carry the meta-analysis audit trail. ``getattr`` for safety
            # in case a custom subclass forgot to set the base attribute.
            filtered_result.meta_filtered_findings = list(
                getattr(result, "meta_filtered_findings", []) or []
            )
            filtered_results.append(filtered_result)

    return filtered_results


def group_findings_by_analyzer(
    findings: List[SecurityFinding],
) -> Dict[str, List[SecurityFinding]]:
    """Group security findings by analyzer type.

    Args:
        findings (List[SecurityFinding]): List of security findings to group.

    Returns:
        Dict[str, List[SecurityFinding]]: Dictionary with analyzer names as keys and finding lists as values.
    """
    analyzer_groups = {}
    for finding in findings:
        analyzer = finding.analyzer
        if analyzer not in analyzer_groups:
            analyzer_groups[analyzer] = []
        analyzer_groups[analyzer].append(finding)
    return analyzer_groups


def get_highest_severity(severities: List[str]) -> str:
    """Get the highest severity from a list of severities.

    Severity model:
    - "UNKNOWN" represents "not yet analyzed" / "analyzer didn't run". It is the
      pre-analysis default and is *displaced* by any concrete severity
      ("HIGH", "MEDIUM", "LOW", "INFO", "SAFE") produced by an analyzer.
    - When concrete severities are present, the highest among them wins.
    - When the list is empty or contains only "UNKNOWN" entries, the result is
      "UNKNOWN" (nothing concrete to roll up).

    Args:
        severities (List[str]): List of severity strings.

    Returns:
        str: The highest severity level.
    """
    severity_order = {
        "HIGH": 5,
        "MEDIUM": 4,
        "LOW": 3,
        "INFO": 2,
        "SAFE": 1,
    }

    concrete = [
        s.upper() for s in severities if s and s.upper() in severity_order
    ]
    if not concrete:
        return "UNKNOWN"

    return max(concrete, key=lambda s: severity_order[s])


def format_results_as_json(
    scan_results: List[
        Union[
            ToolScanResult, PromptScanResult, ResourceScanResult, InstructionsScanResult
        ]
    ],
) -> str:
    """Format scan results as structured JSON grouped by analyzer.

    Args:
        scan_results: List of scan results (tools, prompts, or resources) to format.

    Returns:
        str: JSON formatted string with analyzer-grouped results.
    """
    results = []

    for scan_result in scan_results:
        # Initialize result_dict to None
        result_dict = None

        # Build result dict based on type
        if isinstance(scan_result, ToolScanResult):
            result_dict = {
                "tool_name": scan_result.tool_name,
                "status": scan_result.status,
                "findings": {},
                "is_safe": scan_result.is_safe,
            }
        elif isinstance(scan_result, PromptScanResult):
            result_dict = {
                "prompt_name": scan_result.prompt_name,
                "status": scan_result.status,
                "findings": {},
                "is_safe": scan_result.is_safe,
            }
        elif isinstance(scan_result, ResourceScanResult):
            result_dict = {
                "resource_uri": scan_result.resource_uri,
                "resource_name": scan_result.resource_name,
                "resource_mime_type": scan_result.resource_mime_type,
                "status": scan_result.status,
                "findings": {},
                "is_safe": scan_result.is_safe,
            }
        elif isinstance(scan_result, InstructionsScanResult):
            result_dict = {
                "server_name": scan_result.server_name,
                "protocol_version": scan_result.protocol_version,
                "instructions": scan_result.instructions,
                "status": scan_result.status,
                "findings": {},
                "is_safe": scan_result.is_safe,
            }

        # Skip unknown types
        if result_dict is None:
            continue

        # Group findings by analyzer
        analyzer_groups = group_findings_by_analyzer(scan_result.findings)

        # Always include all analyzers, even if they have no findings
        all_analyzers = ["API", "YARA", "LLM"]
        analyzer_name_mapping = {
            "API": "api_analyzer",
            "YARA": "yara_analyzer",
            "LLM": "llm_analyzer",
        }

        for analyzer in all_analyzers:
            analyzer_key = analyzer.upper()
            analyzer_display_name = analyzer_name_mapping[analyzer]

            if analyzer_key in [a.upper() for a in analyzer_groups.keys()]:
                # Analyzer has findings
                vulns = analyzer_groups.get(
                    analyzer, analyzer_groups.get(analyzer.lower(), [])
                )

                # Extract threat names, severities, and summaries
                threat_names = []
                summaries = []
                severities = []

                # Collect MCP Taxonomy info (use first finding's taxonomy)
                mcp_taxonomy = None
                threat_vuln_classification = None

                for vuln in vulns:
                    severities.append(vuln.severity)

                    # Collect summaries for threat_summary generation
                    if hasattr(vuln, "summary") and vuln.summary:
                        if vuln.summary not in summaries:
                            summaries.append(vuln.summary)

                    # Extract threat name from details
                    if (
                        hasattr(vuln, "details")
                        and vuln.details
                        and "threat_type" in vuln.details
                    ):
                        threat_type = vuln.details["threat_type"]
                        if threat_type not in threat_names:
                            threat_names.append(threat_type)

                    # Collect MCP Taxonomy from first finding
                    if (
                        mcp_taxonomy is None
                        and hasattr(vuln, "mcp_taxonomy")
                        and vuln.mcp_taxonomy
                    ):
                        mcp_taxonomy = vuln.mcp_taxonomy

                    # Collect threat/vulnerability classification from first finding
                    if (
                        threat_vuln_classification is None
                        and hasattr(vuln, "details")
                        and vuln.details
                    ):
                        threat_vuln_classification = vuln.details.get(
                            "threat_vulnerability_classification"
                        )

                # Get the highest severity for this analyzer
                analyzer_severity = get_highest_severity(severities)

                # Get threat_summary from analyzer (each analyzer should provide this)
                if analyzer_severity == "UNKNOWN":
                    threat_summary = "Analysis failed - status unknown"
                    if len(threat_names) == 0 or (
                        len(threat_names) == 1 and threat_names[0].lower() == "unknown"
                    ):
                        threat_names = ["UNKNOWN"]
                elif len(threat_names) == 0:
                    threat_summary = "No specific threats identified"
                else:
                    # Use first summary as threat_summary (analyzers should provide consistent summaries)
                    threat_summary = summaries[0] if summaries else "Threats detected"

                analyzer_finding = {
                    "severity": analyzer_severity,
                    "total_findings": len(vulns),
                    "threat_names": list(set(threat_names)),  # Deduplicate threat names
                    "threat_summary": threat_summary,
                }

                # Add threat/vulnerability classification if available
                if threat_vuln_classification:
                    analyzer_finding["threat_vulnerability_classification"] = (
                        threat_vuln_classification
                    )

                # Add MCP Taxonomy if available (this replaces threat_names and threat_summary)
                if mcp_taxonomy:
                    analyzer_finding["threats"] = mcp_taxonomy
                    # Also add as mcp_taxonomy for CLI display compatibility
                    analyzer_finding["mcp_taxonomy"] = mcp_taxonomy

                result_dict["findings"][analyzer_display_name] = analyzer_finding
            else:
                # Analyzer has no findings - set default values
                result_dict["findings"][analyzer_display_name] = {
                    "severity": "SAFE",
                    "total_findings": 0,
                }

        # H3 fix: surface the meta-analysis audit trail on the SDK
        # JSON serializer too. Previously only ``report_generator`` (CLI
        # artifacts) and ``api/router`` (HTTP responses) emitted this
        # block, so SDK consumers following ``docs/architecture.md`` and
        # ``docs/behavioral-scanning.md`` would miss every dropped FP and
        # see a clean-looking ``is_safe: true`` report. Delegate to the
        # shared ``build_meta_audit_payload`` so the three serializers
        # stay byte-identical.
        meta_audit = build_meta_audit_payload(
            getattr(scan_result, "meta_filtered_findings", None) or []
        )
        if meta_audit is not None:
            result_dict["meta_analysis"] = meta_audit

        results.append(result_dict)

    return json.dumps({"scan_results": results}, indent=2)


def format_results_by_analyzer(
    scan_result: Union[
        ToolScanResult, PromptScanResult, ResourceScanResult, InstructionsScanResult
    ],
) -> str:
    """Format scan results grouped by analyzer for display.

    Args:
        scan_result: The scan result (tool, prompt, or resource) to format.

    Returns:
        str: Formatted string showing results grouped by analyzer.
    """
    # Get the item name based on type
    if isinstance(scan_result, ToolScanResult):
        item_name = f"Tool '{scan_result.tool_name}'"
    elif isinstance(scan_result, PromptScanResult):
        item_name = f"Prompt '{scan_result.prompt_name}'"
    elif isinstance(scan_result, ResourceScanResult):
        item_name = f"Resource '{scan_result.resource_uri}'"
    elif isinstance(scan_result, InstructionsScanResult):
        item_name = f"Instructions from '{scan_result.server_name}'"
    else:
        item_name = "Item"

    # H3 fix: an "is_safe" item that had findings filtered by the
    # meta-analyzer is NOT just "safe — no threats detected"; it's
    # "safe AFTER the meta-analyzer dropped N findings as false
    # positives". Surface that distinction so SDK / CLI users of this
    # markdown serializer can see when filtering happened. Keep the
    # original safe-emoji-only output when nothing was dropped (avoids
    # confusing operators on truly clean tools).
    meta_dropped = list(getattr(scan_result, "meta_filtered_findings", []) or [])
    if scan_result.is_safe:
        if not meta_dropped:
            return f"✅ {item_name} is safe - no potential threats detected"
        # Filtered-clean case: explicit so the audit trail is visible.
        suffix_lines = [
            f"✅ {item_name} is safe — no findings remained after meta-analysis",
            f"ℹ️  Meta-analyzer dropped {len(meta_dropped)} finding(s) as false positives:",
        ]
        for f in meta_dropped:
            details = getattr(f, "details", {}) or {}
            reason = details.get("meta_reason", "Identified as likely false positive")
            suffix_lines.append(
                f"  • [{f.analyzer}/{f.severity}] {f.summary} — {reason}"
            )
        return "\n".join(suffix_lines)

    output = [f"🚨 {item_name} - Found {len(scan_result.findings)} potential threats\n"]

    # Group findings by analyzer
    analyzer_groups = group_findings_by_analyzer(scan_result.findings)

    # Display results grouped by analyzer
    for analyzer, vulns in analyzer_groups.items():
        output.append(f"🔍 {analyzer.upper()} ANALYZER ({len(vulns)} findings):")
        for vuln in vulns:
            output.append(f"  • {vuln.severity}: {vuln.summary}")
        output.append("")  # Empty line between analyzers

    # Audit trail: even on unsafe results, dropped FPs should be visible
    # so an operator inspecting the report knows the meta pass did
    # something. Use the same one-line-per-finding shape as the safe
    # branch above for consistency.
    if meta_dropped:
        output.append(
            f"ℹ️  Meta-analyzer dropped {len(meta_dropped)} additional finding(s) as false positives:"
        )
        for f in meta_dropped:
            details = getattr(f, "details", {}) or {}
            reason = details.get("meta_reason", "Identified as likely false positive")
            output.append(
                f"  • [{f.analyzer}/{f.severity}] {f.summary} — {reason}"
            )

    return "\n".join(output)
