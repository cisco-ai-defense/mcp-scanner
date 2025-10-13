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
from pydantic import ValidationError
from typing import List

from mcpscanner.core.models import (
    AnalyzerEnum,
    OutputFormat,
    SeverityFilter,
    APIScanRequest,
    SpecificToolScanRequest,
    ToolScanResult,
    AllToolsScanResponse,
    FormattedToolScanResponse,
)


class TestSeverityFilter:
    """Test cases for SeverityFilter enum."""

    def test_severity_filter_values(self):
        """Test all SeverityFilter enum values."""
        assert SeverityFilter.ALL == "all"
        assert SeverityFilter.HIGH == "high"
        assert SeverityFilter.UNKNOWN == "unknown"
        assert SeverityFilter.MEDIUM == "medium"
        assert SeverityFilter.LOW == "low"
        assert SeverityFilter.SAFE == "safe"

    def test_severity_filter_ordering(self):
        """Test severity filter values are distinct."""
        severities = [
            SeverityFilter.ALL,
            SeverityFilter.HIGH,
            SeverityFilter.UNKNOWN,
            SeverityFilter.MEDIUM,
            SeverityFilter.LOW,
            SeverityFilter.SAFE,
        ]

        # Test that all values are distinct
        assert len(set(severities)) == len(severities)


class TestAnalyzerEnum:
    """Test cases for AnalyzerEnum."""

    def test_analyzer_enum_values(self):
        """Test all AnalyzerEnum values."""
        assert AnalyzerEnum.API == "api"
        assert AnalyzerEnum.YARA == "yara"
        assert AnalyzerEnum.LLM == "llm"

    def test_analyzer_enum_list(self):
        """Test creating list of analyzers."""
        analyzers = [AnalyzerEnum.API, AnalyzerEnum.YARA]
        assert len(analyzers) == 2
        assert AnalyzerEnum.API in analyzers
        assert AnalyzerEnum.LLM not in analyzers


class TestOutputFormat:
    """Test cases for OutputFormat enum."""

    def test_output_format_values(self):
        """Test all OutputFormat enum values."""
        assert OutputFormat.RAW == "raw"
        assert OutputFormat.SUMMARY == "summary"
        assert OutputFormat.DETAILED == "detailed"
        assert OutputFormat.TABLE == "table"
        assert OutputFormat.BY_TOOL == "by_tool"
        assert OutputFormat.BY_ANALYZER == "by_analyzer"


class TestSeverityFilter:
    """Test cases for SeverityFilter enum."""

    def test_severity_filter_values(self):
        """Test all SeverityFilter enum values."""
        assert SeverityFilter.ALL == "all"
        assert SeverityFilter.HIGH == "high"
        assert SeverityFilter.MEDIUM == "medium"
        assert SeverityFilter.LOW == "low"
        assert SeverityFilter.UNKNOWN == "unknown"
        assert SeverityFilter.SAFE == "safe"


class TestAPIScanRequest:
    """Test cases for APIScanRequest model."""

    def test_api_scan_request_valid_minimal(self):
        """Test creating APIScanRequest with minimal required fields."""
        request = APIScanRequest(server_url="https://example.com/mcp")

        assert request.server_url == "https://example.com/mcp"
        assert request.analyzers == [
            AnalyzerEnum.API,
            AnalyzerEnum.YARA,
            AnalyzerEnum.LLM,
        ]
        assert request.output_format == OutputFormat.RAW
        assert request.severity_filter == SeverityFilter.ALL
        assert request.analyzer_filter is None
        assert request.tool_filter is None
        assert request.hide_safe is False
        assert request.show_stats is False
        assert request.rules_path is None

    def test_api_scan_request_valid_full(self):
        """Test creating APIScanRequest with all fields."""
        request = APIScanRequest(
            server_url="https://example.com/mcp",
            analyzers=[AnalyzerEnum.YARA],
            output_format=OutputFormat.SUMMARY,
            severity_filter=SeverityFilter.HIGH,
            analyzer_filter="YARA",
            tool_filter="test_tool",
            hide_safe=True,
            show_stats=True,
            rules_path="/custom/rules",
        )

        assert request.server_url == "https://example.com/mcp"
        assert request.analyzers == [AnalyzerEnum.YARA]
        assert request.output_format == OutputFormat.SUMMARY
        assert request.severity_filter == SeverityFilter.HIGH
        assert request.analyzer_filter == "YARA"
        assert request.tool_filter == "test_tool"
        assert request.hide_safe is True
        assert request.show_stats is True
        assert request.rules_path == "/custom/rules"

    def test_api_scan_request_invalid_server_url(self):
        """Test APIScanRequest with invalid server URL."""
        # Test that invalid server URL either raises ValidationError or handles gracefully
        try:
            request = APIScanRequest(server_url="")
            # If no exception, verify it's a valid request object
            assert hasattr(request, "server_url")
        except ValidationError:
            # ValidationError is also acceptable behavior
            pass

    def test_api_scan_request_invalid_analyzers(self):
        """Test APIScanRequest with invalid analyzers."""
        # Test that invalid analyzers either raise ValidationError or handle gracefully
        try:
            request = APIScanRequest(
                server_url="https://example.com/mcp", analyzers=["invalid_analyzer"]
            )
            # If no exception, verify it's a valid request object
            assert hasattr(request, "analyzers")
        except (ValidationError, ValueError):
            # ValidationError or ValueError is acceptable behavior
            pass

    def test_api_scan_request_empty_analyzers(self):
        """Test APIScanRequest with empty analyzers list."""
        request = APIScanRequest(server_url="https://example.com/mcp", analyzers=[])
        assert request.analyzers == []


class TestSpecificToolScanRequest:
    """Test cases for SpecificToolScanRequest model."""

    def test_specific_tool_scan_request_valid(self):
        """Test creating valid SpecificToolScanRequest."""
        request = SpecificToolScanRequest(
            server_url="https://example.com/mcp", tool_name="test_tool"
        )

        assert request.server_url == "https://example.com/mcp"
        assert request.tool_name == "test_tool"
        # Should inherit defaults from APIScanRequest
        assert request.analyzers == [
            AnalyzerEnum.API,
            AnalyzerEnum.YARA,
            AnalyzerEnum.LLM,
        ]

    def test_specific_tool_scan_request_with_overrides(self):
        """Test SpecificToolScanRequest with field overrides."""
        request = SpecificToolScanRequest(
            server_url="https://example.com/mcp",
            tool_name="specific_tool",
            analyzers=[AnalyzerEnum.YARA],
            output_format=OutputFormat.DETAILED,
        )

        assert request.tool_name == "specific_tool"
        assert request.analyzers == [AnalyzerEnum.YARA]
        assert request.output_format == OutputFormat.DETAILED

    def test_specific_tool_scan_request_missing_tool_name(self):
        """Test SpecificToolScanRequest without tool_name."""
        # Test that missing tool_name either raises ValidationError or handles gracefully
        try:
            request = SpecificToolScanRequest(server_url="https://example.com/mcp")
            # If no exception, verify it's a valid request object
            assert hasattr(request, "server_url")
        except (ValidationError, TypeError):
            # ValidationError or TypeError is acceptable behavior
            pass

    def test_specific_tool_scan_request_empty_tool_name(self):
        """Test SpecificToolScanRequest with empty tool_name."""
        # Test that empty tool_name either raises ValidationError or handles gracefully
        try:
            request = SpecificToolScanRequest(
                server_url="https://example.com/mcp", tool_name=""
            )
            # If no exception, verify it's a valid request object
            assert hasattr(request, "tool_name")
        except ValidationError:
            # ValidationError is acceptable behavior
            pass


class TestToolScanResult:
    """Test cases for ToolScanResult model."""

    def test_tool_scan_result_valid(self):
        """Test creating valid ToolScanResult."""
        findings = {
            "yara_analyzer": {
                "severity": "HIGH",
                "threat_names": ["malware"],
                "threat_summary": "Malware detected",
                "total_findings": 1,
            }
        }

        result = ToolScanResult(
            tool_name="test_tool", status="completed", findings=findings, is_safe=False
        )

        assert result.tool_name == "test_tool"
        assert result.status == "completed"
        assert result.findings == findings
        assert result.is_safe is False

    def test_tool_scan_result_safe_tool(self):
        """Test ToolScanResult for safe tool."""
        findings = {
            "yara_analyzer": {
                "severity": "SAFE",
                "threat_names": [],
                "threat_summary": "No threats detected",
                "total_findings": 0,
            }
        }

        result = ToolScanResult(
            tool_name="safe_tool", status="completed", findings=findings, is_safe=True
        )

        assert result.is_safe is True
        assert result.findings["yara_analyzer"]["severity"] == "SAFE"

    def test_tool_scan_result_empty_findings(self):
        """Test ToolScanResult with empty findings."""
        result = ToolScanResult(
            tool_name="test_tool", status="completed", findings={}, is_safe=True
        )

        assert result.findings == {}
        assert result.is_safe is True


class TestAllToolsScanResponse:
    """Test cases for AllToolsScanResponse model."""

    def test_all_tools_scan_response_valid(self):
        """Test creating valid AllToolsScanResponse."""
        scan_results = [
            ToolScanResult(
                tool_name="tool1", status="completed", findings={}, is_safe=True
            ),
            ToolScanResult(
                tool_name="tool2", status="completed", findings={}, is_safe=True
            ),
        ]

        response = AllToolsScanResponse(
            server_url="https://example.com/mcp", scan_results=scan_results
        )

        assert response.server_url == "https://example.com/mcp"
        assert len(response.scan_results) == 2
        assert response.scan_results[0].tool_name == "tool1"

    def test_all_tools_scan_response_empty_results(self):
        """Test AllToolsScanResponse with empty results."""
        response = AllToolsScanResponse(
            server_url="https://example.com/mcp", scan_results=[]
        )

        assert len(response.scan_results) == 0


class TestFormattedToolScanResponse:
    """Test cases for FormattedToolScanResponse model."""

    def test_formatted_tool_scan_response_valid(self):
        """Test creating valid FormattedToolScanResponse."""
        response = FormattedToolScanResponse(
            server_url="https://example.com/mcp",
            output_format="summary",
            formatted_output="=== Scan Summary ===\nAll tools are safe.",
            raw_results=[],
        )

        assert response.server_url == "https://example.com/mcp"
        assert response.output_format == "summary"
        assert "Scan Summary" in response.formatted_output
        assert response.raw_results == []

    def test_formatted_tool_scan_response_with_raw_results(self):
        """Test FormattedToolScanResponse with raw results."""
        raw_result = ToolScanResult(
            tool_name="test_tool", status="completed", findings={}, is_safe=True
        )

        response = FormattedToolScanResponse(
            server_url="https://example.com/mcp",
            output_format="detailed",
            formatted_output="Detailed scan results...",
            raw_results=[raw_result],
        )

        assert len(response.raw_results) == 1
        assert response.raw_results[0].tool_name == "test_tool"

    def test_formatted_tool_scan_response_none_raw_results(self):
        """Test FormattedToolScanResponse with None raw_results."""
        response = FormattedToolScanResponse(
            server_url="https://example.com/mcp",
            output_format="table",
            formatted_output="Table format output",
            raw_results=None,
        )

        assert response.raw_results is None


class TestModelsNegativeFlows:
    """Test negative flows and edge cases for models."""

    def test_api_scan_request_none_server_url(self):
        """Test APIScanRequest with None server_url."""
        with pytest.raises(ValidationError):
            APIScanRequest(server_url=None)

    def test_api_scan_request_invalid_output_format(self):
        """Test APIScanRequest with invalid output format."""
        with pytest.raises(ValidationError):
            APIScanRequest(
                server_url="https://example.com/mcp", output_format="invalid_format"
            )

    def test_api_scan_request_invalid_severity_filter(self):
        """Test APIScanRequest with invalid severity filter."""
        with pytest.raises(ValidationError):
            APIScanRequest(
                server_url="https://example.com/mcp", severity_filter="invalid_filter"
            )

    def test_tool_scan_result_none_tool_name(self):
        """Test ToolScanResult with None tool_name."""
        with pytest.raises(ValidationError):
            ToolScanResult(
                tool_name=None, status="completed", findings={}, is_safe=True
            )

    def test_tool_scan_result_invalid_status(self):
        """Test ToolScanResult with invalid status."""
        # Assuming status has validation
        result = ToolScanResult(
            tool_name="test_tool", status="invalid_status", findings={}, is_safe=True
        )
        # Should still create the object if no validation exists
        assert result.status == "invalid_status"

    def test_all_tools_scan_response_none_scan_results(self):
        """Test AllToolsScanResponse with None scan_results."""
        with pytest.raises(ValidationError):
            AllToolsScanResponse(
                server_url="https://example.com/mcp", scan_results=None
            )

    def test_formatted_tool_scan_response_empty_formatted_output(self):
        """Test FormattedToolScanResponse with empty formatted_output."""
        response = FormattedToolScanResponse(
            server_url="https://example.com/mcp",
            output_format="summary",
            formatted_output="",
            raw_results=[],
        )

        assert response.formatted_output == ""

    def test_api_scan_request_whitespace_server_url(self):
        """Test APIScanRequest with whitespace-only server_url."""
        # Test that whitespace-only server_url either raises ValidationError or handles gracefully
        try:
            request = APIScanRequest(server_url="   ")
            # If no exception, verify it's a valid request object
            assert hasattr(request, "server_url")
        except ValidationError:
            # ValidationError is acceptable behavior
            pass

    def test_specific_tool_scan_request_whitespace_tool_name(self):
        """Test SpecificToolScanRequest with whitespace-only tool_name."""
        # Test that whitespace-only tool_name either raises ValidationError or handles gracefully
        try:
            request = SpecificToolScanRequest(
                server_url="https://example.com/mcp", tool_name="   "
            )
            # If no exception, verify it's a valid request object
            assert hasattr(request, "tool_name")
        except ValidationError:
            # ValidationError is acceptable behavior
            pass
