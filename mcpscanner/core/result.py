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
from typing import Any, Dict, List

from .analyzers.base import SecurityFinding


class ScanResult:
    """Aggregates all findings from a scan.

    Attributes:
        tool_name (str): The name of the scanned tool.
        tool_description (str): The description of the scanned tool.
        status (str): The status of the scan (e.g., "completed", "failed").
        findings (List[SecurityFinding]): The security findings found during the scan.
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
        """Initialize a new ScanResult instance.

        Args:
            tool_name (str): The name of the scanned tool.
            status (str): The status of the scan.
            findings (List[SecurityFinding]): The security findings found during the scan.
            server_source (str): The source server/config for this result.
            server_name (str): The name of the server from config.
        """
        self.tool_name = tool_name
        self.tool_description = tool_description
        self.status = status
        self.analyzers = analyzers
        self.findings = findings
        self.server_source = server_source
        self.server_name = server_name

    @property
    def is_safe(self) -> bool:
        """Check if the scan result indicates the tool is safe.

        Returns:
            bool: True if no security findings were found, False otherwise.
        """
        return len(self.findings) == 0

    def __str__(self) -> str:
        """Return a string representation of the scan result."""
        return f"ScanResult(tool_name={self.tool_name}, status={self.status}, findings={self.findings})"


def process_scan_results(results: List[ScanResult]) -> Dict[str, Any]:
    """Process a list of scan results and return summary statistics.

    Args:
        results (List[ScanResult]): A list of scan results to process.

    Returns:
        Dict[str, Any]: A dictionary containing summary statistics about the scan results.
    """
    total_tools = len(results)
    safe_tools = [r for r in results if r.is_safe]
    vulnerable_tools = [r for r in results if not r.is_safe]

    # Count findings by severity
    severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "SAFE": 0, "UNKNOWN": 0}
    threat_types = {}

    for result in vulnerable_tools:
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

    return {
        "total_tools": total_tools,
        "safe_tools": len(safe_tools),
        "vulnerable_tools": len(vulnerable_tools),
        "severity_counts": severity_counts,
        "threat_types": threat_types,
        "results": results,
    }


def filter_results_by_severity(
    results: List[ScanResult], severity: str
) -> List[ScanResult]:
    """Filter scan results by severity level.

    Args:
        results (List[ScanResult]): A list of scan results to filter.
        severity (str): The severity level to filter by (high, medium, low).

    Returns:
        List[ScanResult]: A filtered list of scan results.
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
            # Create a new ScanResult with only the filtered findings
            filtered_result = ScanResult(
                tool_name=result.tool_name,
                tool_description=result.tool_description,
                status=result.status,
                analyzers=result.analyzers,
                findings=filtered_findings,
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

    Args:
        severities (List[str]): List of severity strings.

    Returns:
        str: The highest severity level.
    """
    severity_order = {"HIGH": 5, "UNKNOWN": 4, "MEDIUM": 3, "LOW": 2, "SAFE": 1}
    highest = "SAFE"
    highest_value = 0

    for severity in severities:
        value = severity_order.get(severity.upper(), 0)
        if value > highest_value:
            highest_value = value
            highest = severity.upper()

    return highest


def format_results_as_json(scan_results: List[ScanResult]) -> str:
    """Format scan results as structured JSON grouped by analyzer.

    Args:
        scan_results (List[ScanResult]): List of scan results to format.

    Returns:
        str: JSON formatted string with analyzer-grouped results.
    """
    results = []

    for scan_result in scan_results:
        tool_result = {
            "tool_name": scan_result.tool_name,
            "status": scan_result.status,
            "findings": {},
            "is_safe": scan_result.is_safe,
        }

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

                tool_result["findings"][analyzer_display_name] = {
                    "severity": analyzer_severity,
                    "threat_names": threat_names,
                    "threat_summary": threat_summary,
                    "total_findings": len(vulns),
                }
            else:
                # Analyzer has no findings - set default values
                tool_result["findings"][analyzer_display_name] = {
                    "severity": "SAFE",
                    "threat_names": [],
                    "threat_summary": "N/A",
                    "total_findings": 0,
                }

        results.append(tool_result)

    return json.dumps({"scan_results": results}, indent=2)


def format_results_by_analyzer(scan_result: ScanResult) -> str:
    """Format scan results grouped by analyzer for display.

    Args:
        scan_result (ScanResult): The scan result to format.

    Returns:
        str: Formatted string showing results grouped by analyzer.
    """
    if scan_result.is_safe:
        return (
            f"✅ Tool '{scan_result.tool_name}' is safe - no potential threats detected"
        )

    output = [
        f"🚨 Tool '{scan_result.tool_name}' - Found {len(scan_result.findings)} potential threats\n"
    ]

    # Group findings by analyzer
    analyzer_groups = group_findings_by_analyzer(scan_result.findings)

    # Display results grouped by analyzer
    for analyzer, vulns in analyzer_groups.items():
        output.append(f"🔍 {analyzer.upper()} ANALYZER ({len(vulns)} findings):")
        for vuln in vulns:
            output.append(f"  • {vuln.severity}: {vuln.summary}")
        output.append("")  # Empty line between analyzers

    return "\n".join(output)
