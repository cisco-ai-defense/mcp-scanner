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

import pytest
from unittest.mock import Mock, patch, mock_open
from typing import List, Dict, Any

from mcpscanner.core.report_generator import ReportGenerator, results_to_json
from mcpscanner.core.result import ToolScanResult, PromptScanResult, ResourceScanResult
from mcpscanner.core.analyzers.base import SecurityFinding
from mcpscanner.core.models import OutputFormat, SeverityFilter
from mcpscanner.config.constants import SeverityLevel


def convert_scan_results_to_dict(scan_results):
    """Convert ScanResult objects to dictionary format expected by ReportGenerator."""
    dict_results = []
    for result in scan_results:
        # Group findings by analyzer
        findings_by_analyzer = {}
        for finding in result.findings:
            analyzer_key = finding.analyzer.lower() + "_analyzer"
            if analyzer_key not in findings_by_analyzer:
                findings_by_analyzer[analyzer_key] = {
                    "severity": "SAFE",
                    "threat_names": [],
                    "threat_summary": "N/A",
                    "total_findings": 0,
                    "findings": [],
                }

            findings_by_analyzer[analyzer_key]["threat_names"].append(
                finding.threat_category
            )
            findings_by_analyzer[analyzer_key]["total_findings"] += 1
            findings_by_analyzer[analyzer_key]["findings"].append(
                {
                    "severity": finding.severity,
                    "message": finding.summary,
                    "analyzer": finding.analyzer,
                    "threat_category": finding.threat_category,
                    "details": finding.details,
                }
            )

            # Update overall severity
            if finding.severity in ["CRITICAL", "HIGH"]:
                findings_by_analyzer[analyzer_key]["severity"] = "HIGH"
            elif (
                finding.severity == "MEDIUM"
                and findings_by_analyzer[analyzer_key]["severity"] == "SAFE"
            ):
                findings_by_analyzer[analyzer_key]["severity"] = "MEDIUM"

        dict_result = {
            "tool_name": result.tool_name,
            "status": result.status,
            "findings": findings_by_analyzer,
            "is_safe": result.is_safe,
        }
        dict_results.append(dict_result)

    return dict_results


class TestReportGenerator:
    """Test cases for ReportGenerator class."""

    def test_report_generator_creation_with_results(self):
        """Test creating ReportGenerator with scan results."""
        findings = [
            SecurityFinding(SeverityLevel.HIGH, "Test finding", "YARA", "test_category")
        ]
        results = [
            ToolScanResult("tool1", "Tool 1 description", "completed", ["YARA"], findings)
        ]
        dict_results = convert_scan_results_to_dict(results)
        scan_data = {
            "server_url": "http://test-server.com",
            "scan_results": dict_results,
            "requested_analyzers": ["yara", "api", "llm"],
        }

        generator = ReportGenerator(scan_data)

        assert generator.scan_results == dict_results
        assert len(generator.scan_results) == 1

    def test_report_generator_creation_empty_results(self):
        """Test creating ReportGenerator with empty results."""
        scan_data = {
            "server_url": "http://test-server.com",
            "scan_results": [],
            "requested_analyzers": [],
        }
        generator = ReportGenerator(scan_data)

        assert generator.scan_results == []
        assert len(generator.scan_results) == 0

    def test_report_generator_format_output_summary(self):
        """Test formatting output as summary."""
        findings = [
            SecurityFinding(
                SeverityLevel.HIGH, "High severity finding", "YARA", "test_category"
            )
        ]
        results = [
            ToolScanResult("tool1", "Tool 1 description", "completed", ["YARA"], findings),
            ToolScanResult("tool2", "Tool 2 description", "completed", [], []),
        ]

        dict_results = convert_scan_results_to_dict(results)
        scan_data = {
            "server_url": "http://test-server.com",
            "scan_results": dict_results,
            "requested_analyzers": ["yara", "api", "llm"],
        }
        generator = ReportGenerator(scan_data)
        output = generator.format_output(OutputFormat.SUMMARY)

        assert "=== MCP Scanner Results Summary ===" in output
        assert "Total tools scanned: 2" in output
        assert "Safe items: 1" in output
        assert "Unsafe items: 1" in output

    def test_report_generator_format_output_detailed(self):
        """Test formatting output as detailed."""
        findings = [
            SecurityFinding(
                SeverityLevel.MEDIUM, "Medium severity finding", "YARA", "test_category"
            )
        ]
        results = [
            ToolScanResult(
                "test_tool", "Test tool description", "completed", ["YARA"], findings
            )
        ]

        dict_results = convert_scan_results_to_dict(results)
        scan_data = {
            "server_url": "http://test-server.com",
            "scan_results": dict_results,
            "requested_analyzers": ["yara", "api", "llm"],
        }
        generator = ReportGenerator(scan_data)
        output = generator.format_output(OutputFormat.DETAILED)

        assert "=== MCP Scanner Detailed Results ===" in output
        assert "Tool 1: test_tool" in output
        assert "Status: completed" in output
        assert "Safe: No" in output
        assert "yara_analyzer" in output
        assert "MEDIUM" in output

    def test_report_generator_format_output_table(self):
        """Test formatting output as table."""
        findings = [
            SecurityFinding(
                SeverityLevel.LOW, "Low severity finding", "API", "test_category"
            )
        ]
        results = [
            ToolScanResult(
                "table_tool", "Table tool description", "completed", ["API"], findings
            )
        ]

        dict_results = convert_scan_results_to_dict(results)
        scan_data = {
            "server_url": "http://test-server.com",
            "scan_results": dict_results,
            "requested_analyzers": ["yara", "api", "llm"],
        }
        generator = ReportGenerator(scan_data)
        output = generator.format_output(OutputFormat.TABLE)

        assert "Tool Name" in output
        assert "Status" in output
        assert "SAFE" in output
        assert "API" in output
        assert "table_tool" in output

    def test_report_generator_format_output_by_tool(self):
        """Test formatting output by tool."""
        findings1 = [
            SecurityFinding(SeverityLevel.HIGH, "Finding 1", "YARA", "test_category")
        ]
        findings2 = [
            SecurityFinding(SeverityLevel.MEDIUM, "Finding 2", "API", "test_category")
        ]
        results = [
            ToolScanResult("tool1", "Tool 1 description", "completed", ["YARA"], findings1),
            ToolScanResult("tool2", "Tool 2 description", "completed", ["API"], findings2),
        ]

        dict_results = convert_scan_results_to_dict(results)
        scan_data = {
            "server_url": "http://test-server.com",
            "scan_results": dict_results,
            "requested_analyzers": ["yara", "api", "llm"],
        }
        generator = ReportGenerator(scan_data)
        output = generator.format_output(OutputFormat.BY_TOOL)

        assert "=== Results by Tool ===" in output
        assert "tool1" in output
        assert "tool2" in output
        assert "yara_analyzer" in output
        assert "api_analyzer" in output

    def test_report_generator_format_output_by_analyzer(self):
        """Test formatting output by analyzer."""
        findings = [
            SecurityFinding(
                SeverityLevel.HIGH, "YARA finding", "YARA", "test_category"
            ),
            SecurityFinding(
                SeverityLevel.MEDIUM, "API finding", "API", "test_category"
            ),
            SecurityFinding(
                SeverityLevel.LOW, "Another YARA finding", "YARA", "test_category"
            ),
        ]
        results = [
            ToolScanResult(
                "test_tool",
                "Test tool description",
                "completed",
                ["YARA", "API"],
                findings,
            )
        ]

        dict_results = convert_scan_results_to_dict(results)
        scan_data = {
            "server_url": "http://test-server.com",
            "scan_results": dict_results,
            "requested_analyzers": ["yara", "api", "llm"],
        }
        generator = ReportGenerator(scan_data)
        output = generator.format_output(OutputFormat.BY_ANALYZER)

        assert "=== Results by Analyzer ===" in output
        assert "YARA ANALYZER" in output
        assert "API ANALYZER" in output

    def test_report_generator_format_output_raw(self):
        """Test formatting output as raw."""
        findings = [
            SecurityFinding(SeverityLevel.HIGH, "High finding", "LLM", "test_category")
        ]
        results = [
            ToolScanResult(
                "raw_tool", "Raw tool description", "completed", ["LLM"], findings
            )
        ]

        dict_results = convert_scan_results_to_dict(results)
        scan_data = {
            "server_url": "http://test-server.com",
            "scan_results": dict_results,
            "requested_analyzers": ["yara", "api", "llm"],
        }
        generator = ReportGenerator(scan_data)
        output = generator.format_output(OutputFormat.RAW)

        # Raw format should return the results as-is or JSON
        assert isinstance(output, (str, list, dict))

    def test_report_generator_with_severity_filter_high(self):
        """Test ReportGenerator with HIGH severity filter."""
        findings = [
            SecurityFinding(SeverityLevel.LOW, "Low finding", "YARA", "test_category"),
            SecurityFinding(SeverityLevel.HIGH, "High finding", "API", "test_category"),
            SecurityFinding(SeverityLevel.HIGH, "High finding", "LLM", "test_category"),
        ]
        results = [
            ToolScanResult(
                "filtered_tool",
                "Filtered tool description",
                "completed",
                ["API", "LLM"],
                findings,
            )
        ]

        dict_results = convert_scan_results_to_dict(results)
        scan_data = {
            "server_url": "http://test-server.com",
            "scan_results": dict_results,
            "requested_analyzers": ["yara", "api", "llm"],
        }
        generator = ReportGenerator(scan_data)
        output = generator.format_output(
            OutputFormat.DETAILED, severity_filter=SeverityFilter.HIGH
        )

        assert "HIGH" in output
        assert "api_analyzer" in output
        assert "yara_analyzer" not in output

    def test_report_generator_with_severity_filter_medium_and_above(self):
        """Test ReportGenerator with MEDIUM_AND_ABOVE severity filter."""
        findings = [
            SecurityFinding(SeverityLevel.LOW, "Low finding", "YARA", "test_category"),
            SecurityFinding(
                SeverityLevel.MEDIUM, "Medium finding", "API", "test_category"
            ),
            SecurityFinding(SeverityLevel.HIGH, "High finding", "LLM", "test_category"),
        ]
        results = [
            ToolScanResult(
                "filtered_tool",
                "Filtered tool description",
                "completed",
                ["API", "LLM"],
                findings,
            )
        ]

        dict_results = convert_scan_results_to_dict(results)
        scan_data = {
            "server_url": "http://test-server.com",
            "scan_results": dict_results,
            "requested_analyzers": ["yara", "api", "llm"],
        }
        generator = ReportGenerator(scan_data)
        output = generator.format_output(
            OutputFormat.DETAILED, severity_filter=SeverityFilter.MEDIUM
        )

        assert "MEDIUM" in output
        assert "api_analyzer" in output
        assert "yara_analyzer" not in output

    def test_report_generator_with_analyzer_filter(self):
        """Test ReportGenerator with analyzer filter."""
        findings = [
            SecurityFinding(
                SeverityLevel.HIGH, "YARA finding", "YARA", "test_category"
            ),
            SecurityFinding(
                SeverityLevel.MEDIUM, "API finding", "API", "test_category"
            ),
            SecurityFinding(SeverityLevel.LOW, "LLM finding", "LLM", "test_category"),
        ]
        results = [
            ToolScanResult(
                "filtered_tool",
                "Filtered tool description",
                "completed",
                ["API", "LLM"],
                findings,
            )
        ]

        dict_results = convert_scan_results_to_dict(results)
        scan_data = {
            "server_url": "http://test-server.com",
            "scan_results": dict_results,
            "requested_analyzers": ["yara", "api", "llm"],
        }
        generator = ReportGenerator(scan_data)
        output = generator.format_output(
            OutputFormat.DETAILED, analyzer_filter="yara_analyzer"
        )

        assert "yara_analyzer" in output
        assert "api_analyzer" not in output
        assert "llm_analyzer" not in output

    def test_report_generator_with_tool_filter(self):
        """Test ReportGenerator with tool filter."""
        findings1 = [
            SecurityFinding(SeverityLevel.HIGH, "Finding 1", "YARA", "test_category")
        ]
        findings2 = [
            SecurityFinding(SeverityLevel.MEDIUM, "Finding 2", "API", "test_category")
        ]
        results = [
            ToolScanResult(
                "target_tool",
                "Target tool description",
                "completed",
                ["YARA"],
                findings1,
            ),
            ToolScanResult(
                "other_tool", "Other tool description", "completed", ["API"], findings2
            ),
        ]

        dict_results = convert_scan_results_to_dict(results)
        scan_data = {
            "server_url": "http://test-server.com",
            "scan_results": dict_results,
            "requested_analyzers": ["yara", "api", "llm"],
        }
        generator = ReportGenerator(scan_data)
        output = generator.format_output(
            OutputFormat.DETAILED, tool_filter="target_tool"
        )

        assert "target_tool" in output
        assert "yara_analyzer" in output
        assert "other_tool" not in output

    def test_report_generator_hide_safe_tools(self):
        """Test ReportGenerator with hide_safe option."""
        findings = [
            SecurityFinding(
                SeverityLevel.HIGH, "Unsafe finding", "YARA", "test_category"
            )
        ]
        results = [
            ToolScanResult(
                "unsafe_tool",
                "Unsafe tool description",
                "completed",
                ["YARA"],
                findings,
            ),
            ToolScanResult("safe_tool", "Safe tool description", "completed", [], []),
        ]

        dict_results = convert_scan_results_to_dict(results)
        scan_data = {
            "server_url": "http://test-server.com",
            "scan_results": dict_results,
            "requested_analyzers": ["yara", "api", "llm"],
        }
        generator = ReportGenerator(scan_data)
        output = generator.format_output(OutputFormat.DETAILED, show_safe=False)

        assert "unsafe_tool" in output
        # Check that only unsafe_tool appears, not safe_tool
        assert "Tool 1: unsafe_tool" in output
        assert "Tool 2:" not in output  # Safe tool should not appear as Tool 2

    def test_report_generator_show_statistics(self):
        """Test ReportGenerator with statistics enabled."""
        findings = [
            SecurityFinding(
                SeverityLevel.HIGH, "High finding", "YARA", "test_category"
            ),
            SecurityFinding(
                SeverityLevel.MEDIUM, "Medium finding", "API", "test_category"
            ),
        ]
        results = [
            ToolScanResult(
                "stats_tool",
                "Stats tool description",
                "completed",
                ["YARA", "API"],
                findings,
            )
        ]

        dict_results = convert_scan_results_to_dict(results)
        scan_data = {
            "server_url": "http://test-server.com",
            "scan_results": dict_results,
            "requested_analyzers": ["yara", "api", "llm"],
        }
        generator = ReportGenerator(scan_data)
        output = generator.format_output(OutputFormat.SUMMARY)

        assert "Statistics" in output or "stats" in output.lower()


class TestResultsToJson:
    """Test cases for results_to_json function."""

    @pytest.mark.asyncio
    async def test_results_to_json_valid_results(self):
        """Test converting valid results to JSON."""
        findings = [
            SecurityFinding(
                SeverityLevel.HIGH,
                "High finding",
                "YARA",
                "test_category",
                {"rule": "test_rule"},
            )
        ]
        results = [
            ToolScanResult("tool1", "Tool 1 description", "completed", ["YARA"], findings),
            ToolScanResult("tool2", "Tool 2 description", "completed", [], []),
        ]

        json_results = await results_to_json(results)

        assert len(json_results) == 2
        assert json_results[0]["tool_name"] == "tool1"
        assert json_results[0]["status"] == "completed"
        assert json_results[0]["is_safe"] is False
        assert len(json_results[0]["findings"]) == 1

        assert json_results[1]["tool_name"] == "tool2"
        assert json_results[1]["is_safe"] is True
        assert len(json_results[1]["findings"]) == 0

    @pytest.mark.asyncio
    async def test_results_to_json_empty_results(self):
        """Test converting empty results to JSON."""
        json_results = await results_to_json([])
        assert json_results == []

    @pytest.mark.asyncio
    async def test_results_to_json_with_error(self):
        """Test converting results with error to JSON."""
        result = ToolScanResult("failed_tool", "Failed tool description", "failed", [], [])
        json_results = await results_to_json([result])

        assert len(json_results) == 1
        assert json_results[0]["status"] == "failed"

    @pytest.mark.asyncio
    async def test_results_to_json_finding_serialization(self):
        """Test that findings are properly serialized."""
        finding = SecurityFinding(
            SeverityLevel.HIGH,
            "High API issue",
            "API",
            "test_category",
            {
                "endpoint": "/api/v1/data",
                "method": "POST",
                "threat_type": "test_category",
            },
        )
        result = ToolScanResult(
            "api_tool", "API tool description", "completed", ["API"], [finding]
        )

        json_results = await results_to_json([result])

        # Check the structure - findings are grouped by analyzer
        assert "api_analyzer" in json_results[0]["findings"]
        api_findings = json_results[0]["findings"]["api_analyzer"]
        assert api_findings["severity"] == "HIGH"
        assert api_findings["total_findings"] == 1
        assert "test_category" in api_findings["threat_names"]


class TestReportGeneratorNegativeFlows:
    """Test negative flows and edge cases for ReportGenerator."""

    def test_report_generator_none_results(self):
        """Test ReportGenerator with None results."""
        with pytest.raises(AttributeError):
            ReportGenerator(None)

    def test_report_generator_invalid_output_format(self):
        """Test ReportGenerator with invalid output format."""
        results = [ToolScanResult("tool", "Tool description", "completed", [], [])]
        dict_results = convert_scan_results_to_dict(results)
        scan_data = {
            "server_url": "http://test-server.com",
            "scan_results": dict_results,
            "requested_analyzers": ["yara", "api", "llm"],
        }
        generator = ReportGenerator(scan_data)

        # Test that invalid format either raises an exception or returns a string
        try:
            output = generator.format_output("invalid_format")
            # If no exception, verify it returns a string (graceful handling)
            assert isinstance(output, str)
        except (ValueError, AttributeError, TypeError):
            # Exception is also acceptable behavior
            pass

    def test_report_generator_empty_tool_name(self):
        """Test ReportGenerator with empty tool name."""
        results = [ToolScanResult("", "Empty tool description", "completed", [], [])]
        dict_results = convert_scan_results_to_dict(results)
        scan_data = {
            "server_url": "http://test-server.com",
            "scan_results": dict_results,
            "requested_analyzers": ["yara", "api", "llm"],
        }
        generator = ReportGenerator(scan_data)

        output = generator.format_output(OutputFormat.SUMMARY)
        assert isinstance(output, str)

    def test_report_generator_none_finding_message(self):
        """Test ReportGenerator with None finding message."""
        finding = SecurityFinding(SeverityLevel.HIGH, None, "YARA", "test_category")
        results = [
            ToolScanResult("tool", "Tool description", "completed", ["YARA"], [finding])
        ]
        dict_results = convert_scan_results_to_dict(results)
        scan_data = {
            "server_url": "http://test-server.com",
            "scan_results": dict_results,
            "requested_analyzers": ["yara", "api", "llm"],
        }
        generator = ReportGenerator(scan_data)

        output = generator.format_output(OutputFormat.DETAILED)
        assert isinstance(output, str)

    def test_report_generator_invalid_severity_filter(self):
        """Test ReportGenerator with invalid severity filter."""
        results = [ToolScanResult("tool", "Tool description", "completed", [], [])]
        dict_results = convert_scan_results_to_dict(results)
        scan_data = {
            "server_url": "http://test-server.com",
            "scan_results": dict_results,
            "requested_analyzers": ["yara", "api", "llm"],
        }
        generator = ReportGenerator(scan_data)

        # Test that invalid severity filter either raises an exception or handles gracefully
        try:
            output = generator.format_output(
                OutputFormat.SUMMARY, severity_filter="invalid_filter"
            )
            # If no exception, verify it returns a string (graceful handling)
            assert isinstance(output, str)
        except (ValueError, AttributeError, TypeError):
            # Exception is also acceptable behavior
            pass

    def test_report_generator_nonexistent_analyzer_filter(self):
        """Test ReportGenerator with nonexistent analyzer filter."""
        findings = [
            SecurityFinding(SeverityLevel.HIGH, "Finding", "YARA", "test_category")
        ]
        results = [
            ToolScanResult(
                "nonexistent_tool_filter_tool",
                "Tool description",
                "completed",
                ["YARA"],
                findings,
            )
        ]
        dict_results = convert_scan_results_to_dict(results)
        scan_data = {
            "server_url": "http://test-server.com",
            "scan_results": dict_results,
            "requested_analyzers": ["yara", "api", "llm"],
        }
        generator = ReportGenerator(scan_data)

        output = generator.format_output(
            OutputFormat.DETAILED, analyzer_filter="NONEXISTENT"
        )

        # Should return empty or minimal output
        assert isinstance(output, str)
        assert "Finding" not in output

    def test_report_generator_nonexistent_tool_filter(self):
        """Test ReportGenerator with nonexistent tool filter."""
        findings = [
            SecurityFinding(SeverityLevel.HIGH, "Finding", "YARA", "test_category")
        ]
        results = [
            ToolScanResult(
                "existing_tool",
                "Existing tool description",
                "completed",
                ["YARA"],
                findings,
            )
        ]
        dict_results = convert_scan_results_to_dict(results)
        scan_data = {
            "server_url": "http://test-server.com",
            "scan_results": dict_results,
            "requested_analyzers": ["yara", "api", "llm"],
        }
        generator = ReportGenerator(scan_data)

        output = generator.format_output(
            OutputFormat.DETAILED, tool_filter="nonexistent_tool"
        )

        # Should return empty or minimal output
        assert isinstance(output, str)
        assert "existing_tool" not in output

    def test_report_generator_malformed_finding_details(self):
        """Test ReportGenerator with malformed finding details."""
        finding = SecurityFinding(
            SeverityLevel.HIGH,
            "Finding with bad details",
            "YARA",
            "test_category",
            {"nested": {"deeply": {"malformed": None}}},
        )
        results = [
            ToolScanResult("tool", "Tool description", "completed", ["YARA"], [finding])
        ]
        dict_results = convert_scan_results_to_dict(results)
        scan_data = {
            "server_url": "http://test-server.com",
            "scan_results": dict_results,
            "requested_analyzers": ["yara", "api", "llm"],
        }
        generator = ReportGenerator(scan_data)

        output = generator.format_output(OutputFormat.DETAILED)
        assert isinstance(output, str)

    @pytest.mark.asyncio
    async def test_results_to_json_malformed_result(self):
        """Test results_to_json with malformed result."""
        # Create a result with invalid data
        result = ToolScanResult("tool", "Tool description", "completed", [], [])
        result.tool_name = None  # Force invalid state

        # Test that malformed result either raises an exception or handles gracefully
        try:
            json_results = await results_to_json([result])
            # If no exception, verify it returns a list (graceful handling)
            assert isinstance(json_results, list)
        except (TypeError, AttributeError):
            # Exception is also acceptable behavior
            pass

    @pytest.mark.asyncio
    async def test_results_to_json_circular_reference(self):
        """Test results_to_json with circular reference in details."""
        circular_dict = {"key": "value"}
        circular_dict["self"] = circular_dict

        finding = SecurityFinding(
            SeverityLevel.HIGH, "Circular ref", "YARA", "test_category", circular_dict
        )
        result = ToolScanResult(
            "tool", "Tool description", "completed", ["YARA"], [finding]
        )

        # Should handle circular reference gracefully or raise appropriate error
        try:
            json_results = await results_to_json([result])
            # If it succeeds, verify it's handled properly
            assert isinstance(json_results, list)
        except (ValueError, RecursionError):
            # Expected behavior for circular references
            pass

    def test_report_generator_extremely_long_tool_name(self):
        """Test ReportGenerator with extremely long tool name."""
        long_name = "a" * 10000
        results = [
            ToolScanResult(long_name, "Long name tool description", "completed", [], [])
        ]
        dict_results = convert_scan_results_to_dict(results)
        scan_data = {
            "server_url": "http://test-server.com",
            "scan_results": dict_results,
            "requested_analyzers": ["yara", "api", "llm"],
        }
        generator = ReportGenerator(scan_data)

        output = generator.format_output(OutputFormat.DETAILED)
        assert isinstance(output, str)
        assert long_name in output

    def test_report_generator_special_characters_in_names(self):
        """Test ReportGenerator with special characters in names."""
        special_name = "tool!@#$%^&*()_+-={}[]|\\:;\"'<>?,./"
        findings = [
            SecurityFinding(
                SeverityLevel.HIGH, "Special chars", "YARA!@#", "test_category"
            )
        ]
        results = [
            ToolScanResult(
                special_name,
                "Special name tool description",
                "completed",
                ["YARA!@#"],
                findings,
            )
        ]
        dict_results = convert_scan_results_to_dict(results)
        scan_data = {
            "server_url": "http://test-server.com",
            "scan_results": dict_results,
            "requested_analyzers": ["yara", "api", "llm"],
        }
        generator = ReportGenerator(scan_data)

        output = generator.format_output(OutputFormat.DETAILED)
        assert isinstance(output, str)

    def test_report_generator_unicode_characters(self):
        """Test ReportGenerator with Unicode characters."""
        unicode_name = "tool_测试_🔍_αβγ"
        findings = [
            SecurityFinding(
                SeverityLevel.HIGH,
                "Unicode message: 测试🔍αβγ",
                "YARA",
                "test_category",
            )
        ]
        results = [
            ToolScanResult(
                unicode_name,
                "Unicode name tool description",
                "completed",
                ["YARA"],
                findings,
            )
        ]
        dict_results = convert_scan_results_to_dict(results)
        scan_data = {
            "server_url": "http://test-server.com",
            "scan_results": dict_results,
            "requested_analyzers": ["yara", "api", "llm"],
        }
        generator = ReportGenerator(scan_data)

        output = generator.format_output(OutputFormat.DETAILED)
        assert isinstance(output, str)
        assert unicode_name in output


class TestPromptAndResourceResults:
    """Test cases for PromptScanResult and ResourceScanResult."""

    @pytest.mark.asyncio
    async def test_results_to_json_with_prompt_results(self):
        """Test converting prompt results to JSON."""
        findings = [
            SecurityFinding(
                SeverityLevel.HIGH,
                "Prompt injection detected",
                "LLM",
                "PROMPT_INJECTION",
            )
        ]
        results = [
            PromptScanResult(
                "malicious_prompt",
                "A prompt that attempts injection",
                "completed",
                ["LLM"],
                findings
            ),
            PromptScanResult(
                "safe_prompt",
                "A safe prompt",
                "completed",
                [],
                []
            ),
        ]

        json_results = await results_to_json(results)

        assert len(json_results) == 2
        assert json_results[0]["prompt_name"] == "malicious_prompt"
        assert json_results[0]["prompt_description"] == "A prompt that attempts injection"
        assert json_results[0]["item_type"] == "prompt"
        assert json_results[0]["status"] == "completed"
        assert json_results[0]["is_safe"] is False

        assert json_results[1]["prompt_name"] == "safe_prompt"
        assert json_results[1]["item_type"] == "prompt"
        assert json_results[1]["is_safe"] is True

    @pytest.mark.asyncio
    async def test_results_to_json_with_resource_results(self):
        """Test converting resource results to JSON."""
        findings = [
            SecurityFinding(
                SeverityLevel.MEDIUM,
                "Suspicious content detected",
                "LLM",
                "DATA_EXFILTRATION",
            )
        ]
        results = [
            ResourceScanResult(
                "file://test/malicious.html",
                "malicious.html",
                "text/html",
                "completed",
                ["LLM"],
                findings
            ),
            ResourceScanResult(
                "file://test/safe.txt",
                "safe.txt",
                "text/plain",
                "completed",
                [],
                []
            ),
        ]

        json_results = await results_to_json(results)

        assert len(json_results) == 2
        assert json_results[0]["resource_uri"] == "file://test/malicious.html"
        assert json_results[0]["resource_name"] == "malicious.html"
        assert json_results[0]["resource_mime_type"] == "text/html"
        assert json_results[0]["item_type"] == "resource"
        assert json_results[0]["status"] == "completed"
        assert json_results[0]["is_safe"] is False

        assert json_results[1]["resource_uri"] == "file://test/safe.txt"
        assert json_results[1]["item_type"] == "resource"
        assert json_results[1]["is_safe"] is True

    @pytest.mark.asyncio
    async def test_results_to_json_mixed_types(self):
        """Test converting mixed tool, prompt, and resource results to JSON."""
        tool_finding = SecurityFinding(
            SeverityLevel.HIGH, "Tool issue", "YARA", "CODE_EXECUTION"
        )
        prompt_finding = SecurityFinding(
            SeverityLevel.MEDIUM, "Prompt issue", "LLM", "PROMPT_INJECTION"
        )
        resource_finding = SecurityFinding(
            SeverityLevel.LOW, "Resource issue", "LLM", "DATA_EXFILTRATION"
        )

        results = [
            ToolScanResult("test_tool", "Test tool", "completed", ["YARA"], [tool_finding]),
            PromptScanResult("test_prompt", "Test prompt", "completed", ["LLM"], [prompt_finding]),
            ResourceScanResult("file://test.txt", "test.txt", "text/plain", "completed", ["LLM"], [resource_finding]),
        ]

        json_results = await results_to_json(results)

        assert len(json_results) == 3
        
        # Check tool result
        assert json_results[0]["item_type"] == "tool"
        assert json_results[0]["tool_name"] == "test_tool"
        assert "tool_description" in json_results[0]
        
        # Check prompt result
        assert json_results[1]["item_type"] == "prompt"
        assert json_results[1]["prompt_name"] == "test_prompt"
        assert "prompt_description" in json_results[1]
        
        # Check resource result
        assert json_results[2]["item_type"] == "resource"
        assert json_results[2]["resource_uri"] == "file://test.txt"
        assert json_results[2]["resource_name"] == "test.txt"
        assert json_results[2]["resource_mime_type"] == "text/plain"
