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


def _convert_github_scan_result_to_scan_result(github_result):
    """Convert GitHubScanResult to a format compatible with results_to_json.
    
    Args:
        github_result: GitHubScanResult object with structure:
            - findings: dict[analyzer_name, list[dict]] where each dict has:
                - severity: str
                - summary: str
                - details: str (may contain threat_category info)
        
    Returns:
        Mock scan result object with expected attributes
    """
    from .analyzers.base import SecurityFinding
    
    class RepoScanResult:
        def __init__(self, repo_url, status, is_safe, findings_dict, analyzers):
            self.tool_name = repo_url
            self.tool_description = f"Repository scan: {repo_url}"
            self.status = status
            self.is_safe = is_safe
            self.analyzers = [a if isinstance(a, str) else a.value for a in analyzers]
            # Convert findings dict to list of SecurityFinding objects
            self.findings = []
            for analyzer_name, finding_list in findings_dict.items():
                for finding_dict in finding_list:
                    # Get details - could be dict, string, or None
                    details = finding_dict.get("details", {})
                    
                    # Extract threat_category from details
                    threat_category = ""
                    if isinstance(details, dict):
                        # If details is a dict, look for threat_category key
                        threat_category = details.get("threat_category", "")
                    elif isinstance(details, str) and "Category:" in details:
                        # If details is a string, try to extract category
                        for line in details.split('\n'):
                            if line.strip().startswith("Category:"):
                                threat_category = line.split(":", 1)[1].strip()
                                break
                    
                    # Ensure details is a dict for SecurityFinding
                    if not isinstance(details, dict):
                        details = {"raw": str(details)} if details else {}
                    
                    # Create SecurityFinding object from dict
                    self.findings.append(SecurityFinding(
                        severity=finding_dict.get("severity", "unknown"),
                        summary=finding_dict.get("summary", ""),
                        threat_category=threat_category or "Code Vulnerability",
                        details=details,
                        analyzer=analyzer_name,
                    ))
    
    return RepoScanResult(
        repo_url=github_result.repo_url,
        status=github_result.status,
        is_safe=github_result.is_safe,
        findings_dict=github_result.findings,
        analyzers=github_result.analyzers
    )


async def results_to_json(scan_results) -> List[Dict[str, Any]]:
    """Convert scan results to JSON format.

    Note: expects ScanResult-like objects with .findings, .tool_name, .tool_description, .status, .is_safe
    Also handles GitHubScanResult objects by converting them first.

    Args:
        scan_results: List of scan result objects

    Returns:
        List of dictionaries containing formatted scan results
    """
    json_results = []
    for result in scan_results:
        # Check if this is a GitHubScanResult and convert it
        if hasattr(result, 'repo_url') and hasattr(result, 'functions_by_type'):
            result = _convert_github_scan_result_to_scan_result(result)
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
            # Normalize analyzer name to match expected format
            # Convert "CodeLLMAnalyzer" -> "code_llm_analyzer"
            analyzer_name = finding.analyzer
            if analyzer_name == "CodeLLMAnalyzer":
                analyzer = "code_llm_analyzer"
            elif not analyzer_name.lower().endswith("_analyzer"):
                analyzer = analyzer_name.lower() + "_analyzer"
            else:
                analyzer = analyzer_name.lower()
            
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

        result_dict = {
            "tool_name": result.tool_name,
            "tool_description": result.tool_description,
            "status": result.status,
            "is_safe": result.is_safe,
            "findings": findings_by_analyzer,
        }

        # Include server_source if available
        if hasattr(result, "server_source") and result.server_source:
            result_dict["server_source"] = result.server_source

        # Include server_name if available
        if hasattr(result, "server_name") and result.server_name:
            result_dict["server_name"] = result.server_name
        
        # Store raw findings for detailed views (preserve individual finding details)
        if hasattr(result, "findings") and result.findings:
            result_dict["raw_findings"] = [
                {
                    "severity": f.severity,
                    "summary": f.summary,
                    "threat_category": f.threat_category,
                    "details": f.details if isinstance(f.details, str) else f.details,
                    "analyzer": f.analyzer,
                }
                for f in result.findings
            ]

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

    def _format_repo_by_analyzer(
        self, results: List[Dict[str, Any]], analyzer_filter: Optional[str] = None
    ) -> str:
        """Format repository scan results grouped by analyzer."""
        output = ["=== Repository Scan - Results by Analyzer ===\n"]
        
        if not results:
            output.append("No results found.\n")
            return "\n".join(output)
        
        result = results[0]
        repo_url = result.get("tool_name", "Unknown")
        raw_findings = result.get("raw_findings", [])
        findings = result.get("findings", {})
        
        output.append(f"Repository: {repo_url}\n")
        
        # Group findings by analyzer
        for analyzer_name, analyzer_data in findings.items():
            if analyzer_filter and analyzer_filter != analyzer_name:
                continue
            
            severity = analyzer_data.get("severity", "SAFE")
            count = analyzer_data.get("total_findings", 0)
            summary = analyzer_data.get("threat_summary", "No details")
            
            output.append(f"🔍 {analyzer_name.upper().replace('_', ' ')}")
            output.append(f"Severity: {severity}")
            output.append(f"Total Findings: {count}")
            output.append(f"Summary: {summary}")
            
            # Show individual findings for this analyzer
            analyzer_findings = [f for f in raw_findings if f.get("analyzer", "").lower() == analyzer_name.replace("_analyzer", "").lower() or f.get("analyzer") == "CodeLLMAnalyzer"]
            if analyzer_findings and count > 1:  # More than just summary
                output.append("\nKey Findings:")
                vuln_findings = [f for f in analyzer_findings if f.get("threat_category") != "Summary"][:5]
                for i, finding in enumerate(vuln_findings, 1):
                    output.append(f"  {i}. {finding.get('summary', 'No summary')}")
                if len(vuln_findings) < count - 1:
                    output.append(f"  ... and {count - len(vuln_findings) - 1} more")
            
            output.append("")
        
        return "\n".join(output)

    def _format_repo_by_severity(
        self, results: List[Dict[str, Any]], severity_filter: SeverityFilter
    ) -> str:
        """Format repository scan results grouped by severity."""
        output = ["=== Repository Scan - Results by Severity ===\n"]
        
        if not results:
            output.append("No results found.\n")
            return "\n".join(output)
        
        result = results[0]
        repo_url = result.get("tool_name", "Unknown")
        raw_findings = result.get("raw_findings", [])
        
        output.append(f"Repository: {repo_url}\n")
        
        # Group findings by severity (excluding summary findings)
        severity_groups = {
            "HIGH": [],
            "MEDIUM": [],
            "LOW": [],
            "INFO": []
        }
        
        for finding in raw_findings:
            severity = finding.get("severity", "INFO").upper()
            # Skip summary findings
            if finding.get("threat_category") == "Summary":
                continue
            if severity in severity_groups:
                severity_groups[severity].append(finding)
        
        # Display findings by severity
        severity_emojis = {
            "HIGH": "🔴",
            "MEDIUM": "🟡",
            "LOW": "🟢",
            "INFO": "ℹ️"
        }
        
        severity_order = ["HIGH", "MEDIUM", "LOW", "INFO"]
        for severity in severity_order:
            findings_list = severity_groups[severity]
            
            # Apply severity filter
            if severity_filter != SeverityFilter.ALL and severity_filter.value.upper() != severity:
                continue
            
            if not findings_list:
                continue
            
            emoji = severity_emojis.get(severity, "ℹ️")
            output.append(f"{emoji} {severity} SEVERITY ({len(findings_list)} findings)")
            
            # Show first 10 findings
            for i, finding in enumerate(findings_list[:10], 1):
                category = finding.get('threat_category', 'Unknown')
                summary = finding.get('summary', 'No summary')
                output.append(f"  {i}. [{category}] {summary}")
            
            if len(findings_list) > 10:
                output.append(f"  ... and {len(findings_list) - 10} more")
            
            output.append("")
        
        return "\n".join(output)

    def _format_repo_table(self, results: List[Dict[str, Any]]) -> str:
        """Format repository scan results as a table."""
        output = ["=== MCP Scanner Results Table ===\n"]
        
        if not results:
            output.append("No results found.\n")
            return "\n".join(output)
        
        result = results[0]
        repo_url = result.get("tool_name", "Unknown")
        is_safe = result.get("is_safe", True)
        raw_findings = result.get("raw_findings", [])
        findings = result.get("findings", {})
        
        # Group findings by function/vulnerability
        vulnerability_findings = [f for f in raw_findings if f.get("threat_category") != "Summary"]
        
        # Create table header matching the standard format
        header = f"{'Repository':<30} {'Vulnerability':<35} {'Status':<10} {'CODE_LLM':<10} {'Severity':<10}"
        output.append(header)
        output.append("—" * (len(header) + 10))
        
        # Get analyzer severity
        code_llm_severity = findings.get("code_llm_analyzer", {}).get("severity", "N/A")
        
        severity_emojis = {
            "HIGH": "🔴",
            "MEDIUM": "🟠",
            "LOW": "🟡",
            "SAFE": "🟢",
        }
        
        if not vulnerability_findings:
            # No vulnerabilities found
            repo_short = repo_url[:28]
            status = "SAFE"
            severity_emoji = severity_emojis.get("SAFE", "🟢")
            overall_severity = f"{severity_emoji} SAFE"
            row = f"{repo_short:<30} {'No vulnerabilities':<35} {status:<10} {code_llm_severity:<10} {overall_severity:<10}"
            output.append(row)
        else:
            # Show all vulnerabilities
            for i, finding in enumerate(vulnerability_findings, 1):
                if i == 1:
                    repo_display = repo_url[:28]
                else:
                    repo_display = ""  # Empty for subsequent rows
                
                # Extract function name from summary
                summary = finding.get("summary", "Unknown")
                # Try to extract function name from patterns like "X in tool 'function_name'"
                if " in tool '" in summary:
                    vuln_type = summary.split(" in tool '")[0]
                    func_name = summary.split(" in tool '")[1].rstrip("'")
                    vuln_display = f"{func_name}: {vuln_type}"[:33]
                elif " in resource '" in summary:
                    vuln_type = summary.split(" in resource '")[0]
                    func_name = summary.split(" in resource '")[1].rstrip("'")
                    vuln_display = f"{func_name}: {vuln_type}"[:33]
                else:
                    vuln_display = summary[:33]
                
                status = "UNSAFE"
                severity = finding.get("severity", "MEDIUM").upper()
                severity_emoji = severity_emojis.get(severity, "🟠")
                overall_severity = f"{severity_emoji} {severity}"
                
                row = f"{repo_display:<30} {vuln_display:<35} {status:<10} {code_llm_severity:<10} {overall_severity:<10}"
                output.append(row)
        
        return "\n".join(output)

    def _format_repo_detailed(self, results: List[Dict[str, Any]]) -> str:
        """Format repository scan results with detailed vulnerability information."""
        output = ["=== Repository Security Scan - Detailed Results ===\n"]
        
        if not results:
            output.append("No results found.\n")
            return "\n".join(output)
        
        result = results[0]
        repo_url = result.get("tool_name", "Unknown")
        is_safe = result.get("is_safe", True)
        raw_findings = result.get("raw_findings", [])
        
        output.append(f"Repository: {repo_url}")
        output.append(f"Status: {'✅ SAFE' if is_safe else '⚠️  UNSAFE'}")
        output.append(f"Total Vulnerabilities: {len([f for f in raw_findings if f['severity'].upper() in ['HIGH', 'MEDIUM', 'LOW'] and f['threat_category'] != 'Summary'])}\n")
        
        # Group findings by severity (excluding summary findings)
        severity_groups = {
            "HIGH": [],
            "MEDIUM": [],
            "LOW": [],
            "INFO": []
        }
        
        for finding in raw_findings:
            severity = finding.get("severity", "INFO").upper()
            # Skip summary findings
            if finding.get("threat_category") == "Summary":
                continue
            if severity in severity_groups:
                severity_groups[severity].append(finding)
        
        # Display findings by severity
        severity_emojis = {
            "HIGH": "🔴",
            "MEDIUM": "🟡",
            "LOW": "🟢",
            "INFO": "ℹ️"
        }
        
        for severity in ["HIGH", "MEDIUM", "LOW", "INFO"]:
            findings_list = severity_groups[severity]
            if not findings_list:
                continue
            
            emoji = severity_emojis.get(severity, "ℹ️")
            output.append(f"\n{emoji} {severity} SEVERITY ({len(findings_list)} findings)")
            output.append("=" * 60)
            
            for i, finding in enumerate(findings_list, 1):
                output.append(f"\n{i}. {finding.get('summary', 'No summary')}")
                output.append(f"   Category: {finding.get('threat_category', 'Unknown')}")
                
                # Display details
                details = finding.get('details', '')
                if details:
                    if isinstance(details, str):
                        # Format multi-line details
                        for line in details.split('\n'):
                            if line.strip():
                                output.append(f"   {line}")
                    elif isinstance(details, dict):
                        # Format dict details
                        for key, value in details.items():
                            if key != 'raw':
                                output.append(f"   {key}: {value}")
        
        # Show summary at the end
        summary_findings = [f for f in raw_findings if f.get('threat_category') == 'Summary']
        if summary_findings:
            output.append("\n" + "=" * 60)
            output.append(f"\n📊 {summary_findings[0].get('summary', 'Scan complete')}")
        
        return "\n".join(output)

    def _format_repo_summary(self, results: List[Dict[str, Any]]) -> str:
        """Format repository scan results as summary."""
        output = ["=== Repository Security Scan Results ===\n"]
        
        if not results:
            output.append("No results found.\n")
            return "\n".join(output)
        
        result = results[0]
        repo_url = result.get("tool_name", "Unknown")
        is_safe = result.get("is_safe", True)
        findings = result.get("findings", {})
        
        output.append(f"Repository: {repo_url}")
        output.append(f"Status: {'✅ SAFE' if is_safe else '⚠️  UNSAFE'}")
        
        # Count findings by severity
        total_findings = 0
        high_findings = 0
        medium_findings = 0
        low_findings = 0
        
        for analyzer_name, analyzer_data in findings.items():
            severity = analyzer_data.get("severity", "SAFE")
            count = analyzer_data.get("total_findings", 0)
            total_findings += count
            
            if severity == "HIGH":
                high_findings += count
            elif severity == "MEDIUM":
                medium_findings += count
            elif severity == "LOW":
                low_findings += count
        
        output.append(f"\nTotal Findings: {total_findings}")
        if high_findings > 0:
            output.append(f"  🔴 High Severity: {high_findings}")
        if medium_findings > 0:
            output.append(f"  🟡 Medium Severity: {medium_findings}")
        if low_findings > 0:
            output.append(f"  🟢 Low Severity: {low_findings}")
        
        # Show findings by analyzer
        if findings:
            output.append("\n=== Findings by Analyzer ===")
            for analyzer_name, analyzer_data in findings.items():
                severity = analyzer_data.get("severity", "SAFE")
                count = analyzer_data.get("total_findings", 0)
                summary = analyzer_data.get("threat_summary", "No details")
                
                output.append(f"\n{analyzer_name}:")
                output.append(f"  Severity: {severity}")
                output.append(f"  Findings: {count}")
                output.append(f"  Summary: {summary}")
        
        output.append("\n💡 Tip: Use --format detailed to see full vulnerability details")
        
        return "\n".join(output)

    def _format_summary(self, results: List[Dict[str, Any]]) -> str:
        """Format as summary view."""
        output = ["=== MCP Scanner Results Summary ===\n"]

        # Check if this is a repository scan (has repo-specific metadata)
        is_repo_scan = (results and 
                       results[0].get("tool_description", "").startswith("Repository scan:"))
        
        if is_repo_scan:
            # Special formatting for repository scans
            return self._format_repo_summary(results)

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

        output.append(f"Tools matching filters: {len(results)}")
        output.append(f"Safe tools: {safe_count}")
        output.append(f"Unsafe tools: {unsafe_count}")

        unsafe_results = [r for r in results if not r.get("is_safe", True)]

        if unsafe_results:
            output.append("\n=== Unsafe Tools ===")
            for i, result in enumerate(unsafe_results, 1):
                tool_name = result.get("tool_name", "Unknown")
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
                        f"{i}. {tool_name} (Server: {result['server_name']}) - {highest_severity} ({total_findings} findings)"
                    )
                else:
                    output.append(
                        f"{i}. {tool_name} - {highest_severity} ({total_findings} findings)"
                    )

        return "\n".join(output)

    def _format_detailed(self, results: List[Dict[str, Any]]) -> str:
        """Format as detailed view."""
        output = ["=== MCP Scanner Detailed Results ===\n"]

        # Check if this is a repository scan
        is_repo_scan = (results and 
                       results[0].get("tool_description", "").startswith("Repository scan:"))
        
        if is_repo_scan:
            return self._format_repo_detailed(results)

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
            tool_name = result.get("tool_name", "Unknown")
            status = result.get("status", "Unknown")
            is_safe = result.get("is_safe", True)
            findings = result.get("findings", {})

            # Show server name for config-based scans
            if "server_name" in result and result["server_name"]:
                output.append(
                    f"Tool {i}: {tool_name} (Server: {result['server_name']})"
                )
            else:
                output.append(f"Tool {i}: {tool_name}")
            output.append(f"Status: {status}")
            output.append(f"Safe: {'Yes' if is_safe else 'No'}")

            if findings:
                output.append("Analyzer Results:")
                for analyzer, data in findings.items():
                    severity = data.get("severity", "SAFE")
                    threat_names = data.get("threat_names", [])
                    threat_summary = data.get("threat_summary", "N/A")
                    total_findings = data.get("total_findings", 0)

                    output.append(f"  • {analyzer}:")
                    output.append(f"    - Severity: {severity}")
                    output.append(f"    - Threat Summary: {threat_summary}")
                    output.append(
                        f"    - Threat Names: {', '.join(threat_names) if threat_names else 'None'}"
                    )
                    output.append(f"    - Total Findings: {total_findings}")
            else:
                output.append("No findings.")

            output.append("")  # Empty line between tools

        return "\n".join(output)

    def _format_by_tool(self, results: List[Dict[str, Any]]) -> str:
        """Format grouped by tool."""
        # Check if this is a repository scan
        is_repo_scan = (results and 
                       results[0].get("tool_description", "").startswith("Repository scan:"))
        
        if is_repo_scan:
            # For repository scans, by_tool format is the same as summary
            return self._format_repo_summary(results)
        
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
        # Check if this is a repository scan
        is_repo_scan = (results and 
                       results[0].get("tool_description", "").startswith("Repository scan:"))
        
        if is_repo_scan:
            return self._format_repo_by_analyzer(results, analyzer_filter)
        
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
        # Check if this is a repository scan
        is_repo_scan = (results and 
                       results[0].get("tool_description", "").startswith("Repository scan:"))
        
        if is_repo_scan:
            return self._format_repo_by_severity(results, severity_filter)
        
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
        
        # Check if this is a repository scan
        is_repo_scan = (results and 
                       results[0].get("tool_description", "").startswith("Repository scan:"))
        
        if is_repo_scan:
            return self._format_repo_table(results)

        # Check if this is a config-based scan (has server_source)
        has_config_results = any(
            "server_source" in result and result["server_source"] for result in results
        )

        if has_config_results:
            # Table header with Target Server column for config-based scans
            header = f"{'Scan Target':<20} {'Target Server':<20} {'Tool Name':<18} {'Status':<10} {'API':<8} {'YARA':<8} {'LLM':<8} {'Severity':<10}"
        else:
            # Table header without Target Server column for direct server scans
            header = f"{'Scan Target':<30} {'Tool Name':<20} {'Status':<10} {'API':<8} {'YARA':<8} {'LLM':<8} {'Severity':<10}"

        output.append(header)
        output.append("—" * (len(header) + 10))

        for result in results:
            # Use server_source if available, otherwise fall back to server_url
            if "server_source" in result and result["server_source"]:
                scan_target_source = result["server_source"][:18]
            else:
                scan_target_source = self.server_url[:28]

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

            api_severity = get_analyzer_status("api_analyzer")[:6]
            yara_severity = get_analyzer_status("yara_analyzer")[:6]
            llm_severity = get_analyzer_status("llm_analyzer")[:6]

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

            if has_config_results:
                row = f"{scan_target_source:<20} {target_server:<20} {tool_name:<18} {status:<10} {api_severity:<8} {yara_severity:<8} {llm_severity:<8} {overall_severity:<10}"
            else:
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
