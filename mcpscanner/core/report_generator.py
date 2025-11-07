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

"""Report generator module for MCP Scanner SDK.

This module provides comprehensive report generation and formatting capabilities
for MCP security scan results, supporting multiple output formats and filtering options.
"""

import json
from typing import Any, Dict, List, Optional, Union

from .models import OutputFormat, SeverityFilter


async def results_to_json(scan_results) -> List[Dict[str, Any]]:
    """Convert scan results to JSON format.

    Handles ToolScanResult, PromptScanResult, and ResourceScanResult objects.

    Args:
        scan_results: List of scan result objects (ToolScanResult, PromptScanResult, or ResourceScanResult)

    Returns:
        List of dictionaries containing formatted scan results
    """
    json_results = []
    for result in scan_results:
        findings_by_analyzer: Dict[str, Dict[str, Any]] = {}
        summaries_by_analyzer: Dict[str, List[str]] = {}

        # Initialize all requested analyzers as SAFE first
        if hasattr(result, "analyzers"):
            for analyzer in result.analyzers:
                analyzer_name = str(analyzer).lower()
                if hasattr(analyzer, "value"):  # AnalyzerEnum objects
                    analyzer_name = analyzer.value.lower()
                analyzer_key = analyzer_name + "_analyzer"
                findings_by_analyzer[analyzer_key] = {
                    "severity": "SAFE",
                    "threat_names": [],
                    "threat_summary": "No threats detected",
                    "total_findings": 0,
                }
                summaries_by_analyzer[analyzer_key] = []

        # Process actual findings and update analyzer data
        for finding in result.findings:
            analyzer = finding.analyzer.lower() + "_analyzer"
            if analyzer not in findings_by_analyzer:
                findings_by_analyzer[analyzer] = {
                    "severity": "SAFE",
                    "threat_names": [],
                    "threat_summary": "N/A",
                    "total_findings": 0,
                }
                summaries_by_analyzer[analyzer] = []

            findings_by_analyzer[analyzer]["total_findings"] += 1

            # Collect summary from finding
            if hasattr(finding, "summary") and finding.summary:
                if finding.summary not in summaries_by_analyzer[analyzer]:
                    summaries_by_analyzer[analyzer].append(finding.summary)

            threat_type = (
                finding.details.get("threat_type", "unknown")
                if getattr(finding, "details", None)
                else "unknown"
            )
            if threat_type not in findings_by_analyzer[analyzer]["threat_names"]:
                findings_by_analyzer[analyzer]["threat_names"].append(threat_type)
            if finding.severity == "HIGH":
                findings_by_analyzer[analyzer]["severity"] = "HIGH"
            elif (
                findings_by_analyzer[analyzer]["severity"] != "HIGH"
                and finding.severity == "MEDIUM"
            ):
                findings_by_analyzer[analyzer]["severity"] = "MEDIUM"
            elif (
                findings_by_analyzer[analyzer]["severity"] in ["SAFE", "LOW"]
                and finding.severity == "LOW"
            ):
                findings_by_analyzer[analyzer]["severity"] = "LOW"
            
            # Collect MCP Taxonomy from all findings
            if "mcp_taxonomies" not in findings_by_analyzer[analyzer]:
                findings_by_analyzer[analyzer]["mcp_taxonomies"] = []
            
            if hasattr(finding, "mcp_taxonomy") and finding.mcp_taxonomy:
                # Check if this taxonomy is unique (based on aitech + aisubtech)
                taxonomy_key = (finding.mcp_taxonomy.get("aitech"), finding.mcp_taxonomy.get("aisubtech"))
                existing_keys = [(t.get("aitech"), t.get("aisubtech")) for t in findings_by_analyzer[analyzer]["mcp_taxonomies"]]
                
                if taxonomy_key not in existing_keys:
                    findings_by_analyzer[analyzer]["mcp_taxonomies"].append(finding.mcp_taxonomy)

        # Use analyzer-provided summaries for analyzers with findings
        for analyzer, data in findings_by_analyzer.items():
            if data["total_findings"] > 0:
                summaries = summaries_by_analyzer.get(analyzer, [])
                if summaries:
                    # Use first summary as threat_summary (analyzers provide consistent summaries)
                    data["threat_summary"] = summaries[0]
                else:
                    # Fallback to threat_names based summary
                    threat_names = data["threat_names"]
                    if len(threat_names) == 1:
                        data["threat_summary"] = (
                            f"Detected 1 threat: {threat_names[0].replace('_', ' ')}"
                        )
                    else:
                        data["threat_summary"] = (
                            f"Detected {len(threat_names)} threats: {', '.join([t.replace('_', ' ') for t in threat_names])}"
                        )

        # Build result dict based on result type
        result_dict = {
            "status": result.status,
            "is_safe": result.is_safe,
            "findings": findings_by_analyzer,
        }
        
        # Add type-specific fields
        if hasattr(result, "tool_name"):
            # ToolScanResult
            result_dict["tool_name"] = result.tool_name
            result_dict["tool_description"] = result.tool_description
            result_dict["item_type"] = "tool"
        elif hasattr(result, "prompt_name"):
            # PromptScanResult
            result_dict["prompt_name"] = result.prompt_name
            result_dict["prompt_description"] = result.prompt_description
            result_dict["item_type"] = "prompt"
        elif hasattr(result, "resource_uri"):
            # ResourceScanResult
            result_dict["resource_uri"] = result.resource_uri
            result_dict["resource_name"] = result.resource_name
            result_dict["resource_mime_type"] = result.resource_mime_type
            result_dict["item_type"] = "resource"

        # Include server_source if available
        if hasattr(result, "server_source") and result.server_source:
            result_dict["server_source"] = result.server_source

        # Include server_name if available
        if hasattr(result, "server_name") and result.server_name:
            result_dict["server_name"] = result.server_name

        json_results.append(result_dict)
    return json_results


class ReportGenerator:
    """Generates comprehensive reports from MCP scan results in various formats."""

    def __init__(self, scan_data: Union[Dict[str, Any], str]):
        """Initialize the formatter with scan data.

        Args:
            scan_data: Raw scan results as dict or JSON string
        """
        if isinstance(scan_data, str):
            self.data = json.loads(scan_data)
        else:
            self.data = scan_data

        self.server_url = self.data.get("server_url", "Unknown")
        self.scan_results = self.data.get("scan_results", [])
        self.requested_analyzers = self.data.get("requested_analyzers", [])

        # Determine which analyzers were used by checking if any results have findings from them
        self.analyzers_used = set()
        for result in self.scan_results:
            findings = result.get("findings", {})
            for analyzer_key in findings.keys():
                self.analyzers_used.add(analyzer_key)

        # Convert requested analyzer names to the format used in findings
        self.requested_analyzer_keys = set()
        for analyzer in self.requested_analyzers:
            if analyzer.upper() == "YARA":
                self.requested_analyzer_keys.add("yara_analyzer")
            elif analyzer.upper() == "API":
                self.requested_analyzer_keys.add("api_analyzer")
            elif analyzer.upper() == "LLM":
                self.requested_analyzer_keys.add("llm_analyzer")
            elif analyzer.upper() == "BEHAVIORAL":
                self.requested_analyzer_keys.add("behavioral_analyzer")

    def format_output(
        self,
        format_type: OutputFormat = OutputFormat.SUMMARY,
        tool_filter: Optional[str] = None,
        analyzer_filter: Optional[str] = None,
        severity_filter: SeverityFilter = SeverityFilter.ALL,
        show_safe: bool = True,
    ) -> str:
        """Format the output based on specified parameters.

        Args:
            format_type: Type of output format
            tool_filter: Filter by specific tool name
            analyzer_filter: Filter by specific analyzer (api_analyzer, yara_analyzer, llm_analyzer)
            severity_filter: Filter by severity level
            show_safe: Whether to show safe tools

        Returns:
            Formatted output string
        """
        # Apply filters
        filtered_results = self._apply_filters(
            tool_filter, analyzer_filter, severity_filter, show_safe
        )

        # Format based on type
        if format_type == OutputFormat.RAW:
            return self._format_raw()
        if format_type == OutputFormat.SUMMARY:
            return self._format_summary(filtered_results)
        if format_type == OutputFormat.DETAILED:
            return self._format_detailed(filtered_results)
        if format_type == OutputFormat.BY_TOOL:
            return self._format_by_tool(filtered_results)
        if format_type == OutputFormat.BY_ANALYZER:
            return self._format_by_analyzer(filtered_results, analyzer_filter)
        if format_type == OutputFormat.BY_SEVERITY:
            return self._format_by_severity(filtered_results, severity_filter)
        if format_type == OutputFormat.TABLE:
            return self._format_table(filtered_results)
        return self._format_summary(filtered_results)

    def _apply_filters(
        self,
        tool_filter: Optional[str],
        analyzer_filter: Optional[str],
        severity_filter: SeverityFilter,
        show_safe: bool,
    ) -> List[Dict[str, Any]]:
        """Apply filters to scan results."""
        filtered = []

        for result in self.scan_results:
            # Tool name filter
            if (
                tool_filter
                and tool_filter.lower() not in result.get("tool_name", "").lower()
            ):
                continue

            # Safe filter
            if not show_safe and result.get("is_safe", True):
                continue

            # Apply analyzer and severity filters
            if analyzer_filter or severity_filter != SeverityFilter.ALL:
                filtered_result = self._filter_result_findings(
                    result, analyzer_filter, severity_filter
                )
                if filtered_result:
                    filtered.append(filtered_result)
            else:
                filtered.append(result)

        return filtered

    def _filter_result_findings(
        self,
        result: Dict[str, Any],
        analyzer_filter: Optional[str],
        severity_filter: SeverityFilter,
    ) -> Optional[Dict[str, Any]]:
        """Filter findings within a result based on analyzer and severity."""
        findings = result.get("findings", {})
        filtered_findings = {}

        for analyzer, analyzer_data in findings.items():
            # Analyzer filter
            if analyzer_filter and analyzer_filter != analyzer:
                continue

            # Severity filter
            analyzer_severity = analyzer_data.get("severity", "SAFE")
            if severity_filter != SeverityFilter.ALL:
                if severity_filter.value.upper() != analyzer_severity:
                    continue

            filtered_findings[analyzer] = analyzer_data

        if not filtered_findings:
            return None

        # Create filtered result
        filtered_result = result.copy()
        filtered_result["findings"] = filtered_findings
        return filtered_result

    def _format_raw(self) -> str:
        """Format as raw JSON."""
        return json.dumps(self.data, indent=2)

    def _format_summary(self, results: List[Dict[str, Any]]) -> str:
        """Format as summary view."""
        output = ["=== MCP Scanner Results Summary ===\n"]

        # Use server_source if available for config-based scans
        if results and "server_source" in results[0] and results[0]["server_source"]:
            scan_target = results[0]["server_source"]
        else:
            scan_target = self.server_url

        output.append(f"Scan Target: {scan_target}")
        output.append(f"Total tools scanned: {len(self.scan_results)}")

        if not results:
            output.append("No results match the specified filters.\n")
            return "\n".join(output)

        # Count by safety
        safe_count = sum(1 for r in results if r.get("is_safe", True))
        unsafe_count = len(results) - safe_count

        output.append(f"Items matching filters: {len(results)}")
        output.append(f"Safe items: {safe_count}")
        output.append(f"Unsafe items: {unsafe_count}")

        unsafe_results = [r for r in results if not r.get("is_safe", True)]

        if unsafe_results:
            output.append("\n=== Unsafe Items ===")
            for i, result in enumerate(unsafe_results, 1):
                item_type = result.get("item_type", "tool")
                
                # Get item name based on type
                if item_type == "tool":
                    item_name = result.get("tool_name", "Unknown")
                elif item_type == "prompt":
                    item_name = result.get("prompt_name", "Unknown")
                elif item_type == "resource":
                    item_name = result.get("resource_name", "Unknown")
                else:
                    item_name = "Unknown"
                
                findings = result.get("findings", {})

                # Get the highest severity and total findings count
                highest_severity = "SAFE"
                total_findings = 0
                for analyzer_data in findings.values():
                    severity = analyzer_data.get("severity", "SAFE")
                    if self._get_severity_order(severity) > self._get_severity_order(
                        highest_severity
                    ):
                        highest_severity = severity
                    total_findings += analyzer_data.get("total_findings", 0)

                # Show server name for config-based scans
                if "server_name" in result and result["server_name"]:
                    output.append(
                        f"{i}. {item_name} ({item_type}) (Server: {result['server_name']}) - {highest_severity} ({total_findings} findings)"
                    )
                else:
                    output.append(
                        f"{i}. {item_name} ({item_type}) - {highest_severity} ({total_findings} findings)"
                    )

        return "\n".join(output)

    def _format_detailed(self, results: List[Dict[str, Any]]) -> str:
        """Format as detailed view."""
        output = ["=== MCP Scanner Detailed Results ===\n"]

        # Use server_source if available for config-based scans
        if results and "server_source" in results[0] and results[0]["server_source"]:
            scan_target = results[0]["server_source"]
        else:
            scan_target = self.server_url

        output.append(f"Scan Target: {scan_target}\n")

        if not results:
            output.append("No results match the specified filters.\n")
            return "\n".join(output)

        for i, result in enumerate(results, 1):
            item_type = result.get("item_type", "tool")
            status = result.get("status", "Unknown")
            is_safe = result.get("is_safe", True)
            findings = result.get("findings", {})

            # Get item name and description based on type
            if item_type == "tool":
                item_name = result.get("tool_name", "Unknown")
                item_label = "Tool"
            elif item_type == "prompt":
                item_name = result.get("prompt_name", "Unknown")
                item_label = "Prompt"
            elif item_type == "resource":
                item_name = result.get("resource_name", "Unknown")
                item_label = "Resource"
            else:
                item_name = "Unknown"
                item_label = "Item"

            # Show server name for config-based scans
            if "server_name" in result and result["server_name"]:
                output.append(
                    f"{item_label} {i}: {item_name} (Server: {result['server_name']})"
                )
            else:
                output.append(f"{item_label} {i}: {item_name}")
            
            # Add resource-specific info
            if item_type == "resource" and "resource_uri" in result:
                output.append(f"URI: {result['resource_uri']}")
                if "resource_mime_type" in result:
                    output.append(f"MIME Type: {result['resource_mime_type']}")
            
            output.append(f"Status: {status}")
            output.append(f"Safe: {'Yes' if is_safe else 'No'}")

            if findings:
                output.append("Analyzer Results:")
                for analyzer, data in findings.items():
                    severity = data.get("severity", "SAFE")
                    threat_names = data.get("threat_names", [])
                    threat_summary = data.get("threat_summary", "N/A")
                    total_findings = data.get("total_findings", 0)
                    mcp_taxonomy = data.get("mcp_taxonomy")

                    output.append(f"  • {analyzer}:")
                    output.append(f"    - Severity: {severity}")
                    output.append(f"    - Threat Summary: {threat_summary}")
                    output.append(
                        f"    - Threat Names: {', '.join(threat_names) if threat_names else 'None'}"
                    )
                    output.append(f"    - Total Findings: {total_findings}")
                    
                    # Add MCP Taxonomy details if available
                    mcp_taxonomies = data.get("mcp_taxonomies", [])
                    if mcp_taxonomies and total_findings > 0:
                        if len(mcp_taxonomies) == 1:
                            output.append(f"    - MCP Taxonomy:")
                            taxonomy = mcp_taxonomies[0]
                            if taxonomy.get("aitech"):
                                output.append(f"      • AITech: {taxonomy['aitech']}")
                            if taxonomy.get("aitech_name"):
                                output.append(f"      • AITech Name: {taxonomy['aitech_name']}")
                            if taxonomy.get("aisubtech"):
                                output.append(f"      • AISubtech: {taxonomy['aisubtech']}")
                            if taxonomy.get("aisubtech_name"):
                                output.append(f"      • AISubtech Name: {taxonomy['aisubtech_name']}")
                            if taxonomy.get("description"):
                                # Wrap long descriptions
                                desc = taxonomy['description']
                                if len(desc) > 80:
                                    output.append(f"      • Description: {desc[:80]}...")
                                else:
                                    output.append(f"      • Description: {desc}")
                        else:
                            # Multiple taxonomies - show them numbered
                            output.append(f"    - MCP Taxonomies ({len(mcp_taxonomies)} unique threats):")
                            for idx, taxonomy in enumerate(mcp_taxonomies, 1):
                                output.append(f"      [{idx}] {taxonomy.get('aitech_name', 'Unknown')}")
                                if taxonomy.get("aitech"):
                                    output.append(f"          • AITech: {taxonomy['aitech']}")
                                if taxonomy.get("aisubtech"):
                                    output.append(f"          • AISubtech: {taxonomy['aisubtech']}")
                                if taxonomy.get("aisubtech_name"):
                                    output.append(f"          • AISubtech Name: {taxonomy['aisubtech_name']}")
                                if taxonomy.get("description"):
                                    desc = taxonomy['description']
                                    if len(desc) > 80:
                                        output.append(f"          • Description: {desc[:80]}...")
                                    else:
                                        output.append(f"          • Description: {desc}")
            else:
                output.append("No findings.")

            output.append("")  # Empty line between tools

        return "\n".join(output)

    def _format_by_tool(self, results: List[Dict[str, Any]]) -> str:
        """Format grouped by tool."""
        output = ["=== Results by Tool ===\n"]
        output.append(f"Scan Target: {self.server_url}\n")

        if not results:
            output.append("No results match the specified filters.\n")
            return "\n".join(output)

        for result in results:
            tool_name = result.get("tool_name", "Unknown")
            is_safe = result.get("is_safe", True)
            findings = result.get("findings", {})

            # Get summary info
            total_findings = sum(f.get("total_findings", 0) for f in findings.values())
            severities = [f.get("severity", "SAFE") for f in findings.values()]
            highest_severity = self._get_highest_severity(severities)

            # Use colored emojis based on severity
            severity_emojis = {
                "HIGH": "🔴",
                "UNKNOWN": "🔴",
                "MEDIUM": "🟠",
                "LOW": "🟡",
                "SAFE": "🟢",
            }
            severity_icon = severity_emojis.get(highest_severity, "🟢")
            output.append(f"{severity_icon} {tool_name} ({highest_severity})")

            if total_findings > 0:
                output.append(f"   Total findings: {total_findings}")
                for analyzer, data in findings.items():
                    if data.get("total_findings", 0) > 0:
                        threat_summary = data.get("threat_summary", "N/A")
                        output.append(f"   {analyzer}: {threat_summary}")
            else:
                output.append("   No security issues detected")

            output.append("")

        return "\n".join(output)

    def _format_by_analyzer(
        self, results: List[Dict[str, Any]], analyzer_filter: Optional[str] = None
    ) -> str:
        """Format grouped by analyzer."""
        output = ["=== Results by Analyzer ===\n"]
        output.append(f"Scan Target: {self.server_url}\n")

        if not results:
            output.append("No results match the specified filters.\n")
            return "\n".join(output)

        # Group by analyzer
        analyzer_results = {}
        for result in results:
            findings = result.get("findings", {})
            for analyzer, data in findings.items():
                if analyzer_filter and analyzer_filter != analyzer:
                    continue

                if analyzer not in analyzer_results:
                    analyzer_results[analyzer] = []

                analyzer_results[analyzer].append(
                    {"tool_name": result.get("tool_name", "Unknown"), "data": data}
                )

        for analyzer, tools in analyzer_results.items():
            output.append(f"🔍 {analyzer.upper().replace('_', ' ')}")
            output.append(f"Tools analyzed: {len(tools)}")

            # Count by severity
            severity_counts = {}
            for tool in tools:
                severity = tool["data"].get("severity", "SAFE")
                severity_counts[severity] = severity_counts.get(severity, 0) + 1

            output.append(f"Severity breakdown: {dict(severity_counts)}")

            # Show tools with findings
            tools_with_findings = [
                t for t in tools if t["data"].get("total_findings", 0) > 0
            ]
            if tools_with_findings:
                output.append("Tools with findings:")
                for tool in tools_with_findings:
                    tool_name = tool["tool_name"]
                    data = tool["data"]
                    severity = data.get("severity", "SAFE")
                    threat_summary = data.get("threat_summary", "N/A")
                    output.append(f"  • {tool_name} ({severity}): {threat_summary}")

            output.append("")

        return "\n".join(output)

    def _format_by_severity(
        self, results: List[Dict[str, Any]], severity_filter: SeverityFilter
    ) -> str:
        """Format grouped by severity."""
        output = ["=== Results by Severity ===\n"]
        output.append(f"Scan Target: {self.server_url}\n")

        if not results:
            output.append("No results match the specified filters.\n")
            return "\n".join(output)

        # Group by severity
        severity_groups = {}
        for result in results:
            findings = result.get("findings", {})
            for analyzer, data in findings.items():
                severity = data.get("severity", "SAFE")

                if (
                    severity_filter != SeverityFilter.ALL
                    and severity_filter.value.upper() != severity
                ):
                    continue

                if severity not in severity_groups:
                    severity_groups[severity] = []

                severity_groups[severity].append(
                    {
                        "tool_name": result.get("tool_name", "Unknown"),
                        "analyzer": analyzer,
                        "data": data,
                    }
                )

        # Sort by severity priority
        severity_order = ["HIGH", "UNKNOWN", "MEDIUM", "LOW", "SAFE"]
        severity_emojis = {
            "HIGH": "🔴",
            "UNKNOWN": "🔴",
            "MEDIUM": "🟠",
            "LOW": "🟡",
            "SAFE": "🟢",
        }

        for severity in severity_order:
            if severity not in severity_groups:
                continue

            items = severity_groups[severity]
            emoji = severity_emojis.get(severity, "🔴")
            output.append(f"{emoji} {severity} SEVERITY ({len(items)} items)")

            for item in items:
                tool_name = item["tool_name"]
                analyzer = item["analyzer"]
                threat_summary = item["data"].get("threat_summary", "N/A")
                output.append(f"  • {tool_name} [{analyzer}]: {threat_summary}")

            output.append("")

        return "\n".join(output)

    def _format_table(self, results: List[Dict[str, Any]]) -> str:
        """Format as table view."""
        output = ["=== MCP Scanner Results Table ===\n"]

        if not results:
            output.append("No results match the specified filters.\n")
            return "\n".join(output)

        # Check if this is a config-based scan (has server_source)
        has_config_results = any(
            "server_source" in result and result["server_source"] for result in results
        )
        
        # Check if this is a behavioral scan
        is_behavioral = any(
            "behavioral_analyzer" in result.get("findings", {}) for result in results
        )

        if has_config_results:
            # Table header with Target Server column for config-based scans
            header = f"{'Scan Target':<20} {'Target Server':<20} {'Tool Name':<18} {'Status':<10} {'API':<8} {'YARA':<8} {'LLM':<8} {'Severity':<10}"
        elif is_behavioral:
            # Behavioral scan: show only BEHAVIORAL column
            header = f"{'Scan Target':<30} {'Tool Name':<20} {'Status':<10} {'BEHAVIORAL':<15} {'Severity':<10}"
        else:
            # Table header without Target Server column for direct server scans
            header = f"{'Scan Target':<30} {'Tool Name':<20} {'Status':<10} {'API':<8} {'YARA':<8} {'LLM':<8} {'Severity':<10}"

        output.append(header)
        output.append("—" * (len(header) + 10))

        for result in results:
            # Use server_source if available, otherwise fall back to server_url
            if "server_source" in result and result["server_source"]:
                scan_target_source = result["server_source"]
            else:
                scan_target_source = self.server_url
            
            # For behavioral scans, extract just the filename
            if is_behavioral and "behavioral:" in scan_target_source:
                # Extract filename from "behavioral:/path/to/file.py"
                import os
                full_path = scan_target_source.replace("behavioral:", "")
                scan_target_source = os.path.basename(full_path)
            else:
                # Truncate for non-behavioral scans
                scan_target_source = scan_target_source[:28] if not has_config_results else scan_target_source[:18]

            if has_config_results:
                # Config-based scan: show target server
                if "server_name" in result and result["server_name"]:
                    target_server = result["server_name"][:18]
                else:
                    target_server = "unknown"
                tool_name = result.get("tool_name", "Unknown")[:16]
            else:
                # Direct server scan: no target server column
                tool_name = result.get("tool_name", "Unknown")[:18]
            status = "SAFE" if result.get("is_safe", True) else "UNSAFE"
            findings = result.get("findings", {})

            # Get severity for each analyzer
            # Show SAFE only if analyzer was requested AND we have scan results (meaning it ran successfully)
            # Show N/A if analyzer wasn't requested OR if it was requested but failed to run
            def get_analyzer_status(analyzer_key):
                if analyzer_key in findings:
                    return findings[analyzer_key].get("severity", "SAFE")
                elif (
                    analyzer_key in self.requested_analyzer_keys
                    and self.scan_results
                    and result.get("is_safe", True)
                ):
                    # Analyzer was requested and we have results, so it ran successfully and found tools safe
                    return "SAFE"
                else:
                    return "N/A"

            # Get overall severity with colored emoji
            severity_emojis = {
                "HIGH": "🔴",
                "UNKNOWN": "🔴",
                "MEDIUM": "🟠",
                "LOW": "🟡",
                "SAFE": "🟢",
            }

            if findings:
                severities = [f.get("severity", "SAFE") for f in findings.values()]
                severity_text = self._get_highest_severity(severities)
                severity_emoji = severity_emojis.get(severity_text, "🟢")
                overall_severity = f"{severity_emoji} {severity_text}"[:8]
            else:
                severity_emoji = severity_emojis.get(status, "🟢")
                overall_severity = f"{severity_emoji} {status}"[:8]

            if is_behavioral:
                # Behavioral scan: show only behavioral analyzer status
                behavioral_severity = get_analyzer_status("behavioral_analyzer")[:13]
                row = f"{scan_target_source:<30} {tool_name:<20} {status:<10} {behavioral_severity:<15} {overall_severity:<10}"
            elif has_config_results:
                api_severity = get_analyzer_status("api_analyzer")[:6]
                yara_severity = get_analyzer_status("yara_analyzer")[:6]
                llm_severity = get_analyzer_status("llm_analyzer")[:6]
                row = f"{scan_target_source:<20} {target_server:<20} {tool_name:<18} {status:<10} {api_severity:<8} {yara_severity:<8} {llm_severity:<8} {overall_severity:<10}"
            else:
                api_severity = get_analyzer_status("api_analyzer")[:6]
                yara_severity = get_analyzer_status("yara_analyzer")[:6]
                llm_severity = get_analyzer_status("llm_analyzer")[:6]
                row = f"{scan_target_source:<30} {tool_name:<20} {status:<10} {api_severity:<8} {yara_severity:<8} {llm_severity:<8} {overall_severity:<10}"
            output.append(row)

        return "\n".join(output)

    def _get_highest_severity(self, severities: List[str]) -> str:
        """Get the highest severity from a list."""
        severity_order = {"HIGH": 5, "UNKNOWN": 4, "MEDIUM": 3, "LOW": 2, "SAFE": 1}
        highest = "SAFE"
        highest_value = 0

        for severity in severities:
            value = severity_order.get(severity.upper(), 0)
            if value > highest_value:
                highest_value = value
                highest = severity.upper()

        return highest

    def _get_severity_order(self, severity: str) -> int:
        """Get the numeric order value for a severity level."""
        severity_order = {"HIGH": 5, "UNKNOWN": 4, "MEDIUM": 3, "LOW": 2, "SAFE": 1}
        return severity_order.get(severity.upper(), 0)

    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about the scan results."""
        stats = {
            "total_tools": len(self.scan_results),
            "safe_tools": 0,
            "unsafe_tools": 0,
            "severity_counts": {
                "HIGH": 0,
                "UNKNOWN": 0,
                "MEDIUM": 0,
                "LOW": 0,
                "SAFE": 0,
            },
            "analyzer_stats": {
                "api_analyzer": {"total": 0, "with_findings": 0},
                "yara_analyzer": {"total": 0, "with_findings": 0},
                "llm_analyzer": {"total": 0, "with_findings": 0},
            },
        }

        for result in self.scan_results:
            if result.get("is_safe", True):
                stats["safe_tools"] += 1
            else:
                stats["unsafe_tools"] += 1

            findings = result.get("findings", {})
            for analyzer, data in findings.items():
                if analyzer in stats["analyzer_stats"]:
                    stats["analyzer_stats"][analyzer]["total"] += 1
                    if data.get("total_findings", 0) > 0:
                        stats["analyzer_stats"][analyzer]["with_findings"] += 1

                severity = data.get("severity", "SAFE")
                if severity in stats["severity_counts"]:
                    stats["severity_counts"][severity] += 1

        return stats
