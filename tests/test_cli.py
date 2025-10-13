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

"""Unit tests for CLI module."""

import pytest
import json
import tempfile
from pathlib import Path
from unittest.mock import patch, AsyncMock, MagicMock
from typing import List, Dict, Any

from mcpscanner.cli import (
    _get_endpoint_from_env,
    _build_config,
    scan_mcp_server_direct,
    display_results,
)
from mcpscanner import Config, ToolScanResult
from mcpscanner.core.models import AnalyzerEnum
from mcpscanner.core.exceptions import MCPConnectionError


class TestCliHelperFunctions:
    """Test cases for CLI helper functions."""

    def test_get_endpoint_from_env_with_value(self):
        """Test _get_endpoint_from_env with environment variable set."""
        with patch.dict(
            "os.environ", {"MCP_SCANNER_ENDPOINT": "https://test.endpoint.com"}
        ):
            endpoint = _get_endpoint_from_env()
            assert endpoint == "https://test.endpoint.com"

    def test_get_endpoint_from_env_without_value(self):
        """Test _get_endpoint_from_env without environment variable."""
        with patch.dict("os.environ", {}, clear=True):
            endpoint = _get_endpoint_from_env()
            assert endpoint == ""

    def test_build_config_with_api_analyzer(self):
        """Test _build_config with API analyzer selected."""
        analyzers = [AnalyzerEnum.API, AnalyzerEnum.YARA]

        with patch.dict(
            "os.environ",
            {
                "MCP_SCANNER_API_KEY": "test_api_key",
                "MCP_SCANNER_LLM_API_KEY": "test_llm_key",
                "MCP_SCANNER_ENDPOINT": "https://test.com",
            },
        ):
            config = _build_config(analyzers)

            assert config.api_key == "test_api_key"
            assert config.base_url == "https://test.com"
            assert config.llm_provider_api_key == ""  # LLM not selected

    def test_build_config_with_llm_analyzer(self):
        """Test _build_config with LLM analyzer selected."""
        analyzers = [AnalyzerEnum.LLM, AnalyzerEnum.YARA]

        with patch.dict(
            "os.environ",
            {
                "MCP_SCANNER_API_KEY": "test_api_key",
                "MCP_SCANNER_LLM_API_KEY": "test_llm_key",
            },
        ):
            config = _build_config(analyzers)

            assert config.api_key == ""  # API not selected
            assert config.llm_provider_api_key == "test_llm_key"

    def test_build_config_no_analyzers(self):
        """Test _build_config with no analyzers selected."""
        analyzers = []

        with patch.dict(
            "os.environ",
            {
                "MCP_SCANNER_API_KEY": "test_api_key",
                "MCP_SCANNER_LLM_API_KEY": "test_llm_key",
            },
        ):
            config = _build_config(analyzers)

            assert config.api_key == ""
            assert config.llm_provider_api_key == ""

    def test_build_config_no_env_vars(self):
        """Test _build_config without environment variables."""
        analyzers = [AnalyzerEnum.API, AnalyzerEnum.LLM]

        with patch.dict("os.environ", {}, clear=True):
            config = _build_config(analyzers)

            assert config.api_key == ""
            assert config.llm_provider_api_key == ""


class TestScanMcpServerDirect:
    """Test cases for scan_mcp_server_direct function."""

    @pytest.fixture
    def mock_scan_results(self):
        """Mock scan results."""
        return [
            ToolScanResult(
                tool_name="safe_tool",
                tool_description="Safe tool",
                status="completed",
                analyzers=["API"],
                findings=[],
            ),
            ToolScanResult(
                tool_name="unsafe_tool",
                tool_description="Unsafe tool",
                status="completed",
                analyzers=["API"],
                findings=[],
            ),
        ]

    @pytest.mark.asyncio
    async def test_scan_mcp_server_direct_success(self, mock_scan_results):
        """Test successful scan_mcp_server_direct execution."""
        with patch("mcpscanner.cli.Scanner") as mock_scanner_class:
            mock_scanner = AsyncMock()
            mock_scanner.scan_remote_server_tools.return_value = mock_scan_results
            mock_scanner_class.return_value = mock_scanner

            with patch("mcpscanner.cli.results_to_json") as mock_results_to_json:
                mock_results_to_json.return_value = [{"tool_name": "test"}]

                with patch.dict(
                    "os.environ",
                    {
                        "MCP_SCANNER_API_KEY": "test_key",
                        "MCP_SCANNER_LLM_API_KEY": "llm_key",
                    },
                ):
                    results = await scan_mcp_server_direct(
                        "https://test.com", [AnalyzerEnum.API, AnalyzerEnum.YARA]
                    )

                    assert results == [{"tool_name": "test"}]
                    mock_scanner.scan_remote_server_tools.assert_called_once()

    @pytest.mark.asyncio
    async def test_scan_mcp_server_direct_with_output_file(self, mock_scan_results):
        """Test scan_mcp_server_direct with output file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            output_file = f.name

        try:
            with patch("mcpscanner.cli.Scanner") as mock_scanner_class:
                mock_scanner = AsyncMock()
                mock_scanner.scan_remote_server_tools.return_value = mock_scan_results
                mock_scanner_class.return_value = mock_scanner

                with patch("mcpscanner.cli.results_to_json") as mock_results_to_json:
                    mock_results_to_json.return_value = [{"tool_name": "test"}]

                    with patch.dict("os.environ", {"MCP_SCANNER_API_KEY": "test_key"}):
                        results = await scan_mcp_server_direct(
                            "https://test.com",
                            [AnalyzerEnum.API],
                            output_file=output_file,
                        )

                        # Verify file was written
                        assert Path(output_file).exists()
                        with open(output_file, "r") as f:
                            saved_data = json.load(f)
                        assert saved_data == [{"tool_name": "test"}]
        finally:
            Path(output_file).unlink(missing_ok=True)

    @pytest.mark.asyncio
    async def test_scan_mcp_server_direct_verbose_output(
        self, mock_scan_results, capsys
    ):
        """Test scan_mcp_server_direct with verbose output."""
        with patch("mcpscanner.cli.Scanner") as mock_scanner_class:
            mock_scanner = AsyncMock()
            mock_scanner.scan_remote_server_tools.return_value = mock_scan_results
            mock_scanner_class.return_value = mock_scanner

            with patch("mcpscanner.cli.results_to_json") as mock_results_to_json:
                mock_results_to_json.return_value = []

                with patch.dict("os.environ", {"MCP_SCANNER_API_KEY": "test_key"}):
                    await scan_mcp_server_direct(
                        "https://test.com", [AnalyzerEnum.API], verbose=True
                    )

                    captured = capsys.readouterr()
                    assert "Scanning MCP server" in captured.out
                    assert "Analyzers: API" in captured.out
                    assert "Scan completed" in captured.out

    @pytest.mark.asyncio
    async def test_scan_mcp_server_direct_with_custom_rules(
        self, mock_scan_results, capsys
    ):
        """Test scan_mcp_server_direct with custom YARA rules."""
        with patch("mcpscanner.cli.Scanner") as mock_scanner_class:
            mock_scanner = AsyncMock()
            mock_scanner.scan_remote_server_tools.return_value = mock_scan_results
            mock_scanner_class.return_value = mock_scanner

            with patch("mcpscanner.cli.results_to_json") as mock_results_to_json:
                mock_results_to_json.return_value = []

                with patch.dict("os.environ", {"MCP_SCANNER_API_KEY": "test_key"}):
                    await scan_mcp_server_direct(
                        "https://test.com",
                        [AnalyzerEnum.YARA],
                        verbose=True,
                        rules_path="/custom/rules",
                    )

                    captured = capsys.readouterr()
                    assert "Custom YARA Rules: /custom/rules" in captured.out

                    # Verify Scanner was created with custom rules path
                    mock_scanner_class.assert_called_once()
                    call_args = mock_scanner_class.call_args
                    assert call_args.kwargs["rules_dir"] == "/custom/rules"

    @pytest.mark.asyncio
    async def test_scan_mcp_server_direct_connection_error(self, capsys):
        """Test scan_mcp_server_direct with connection error."""
        with patch("mcpscanner.cli.Scanner") as mock_scanner_class:
            mock_scanner = AsyncMock()
            mock_scanner.scan_remote_server_tools.side_effect = MCPConnectionError(
                "Connection failed"
            )
            mock_scanner_class.return_value = mock_scanner

            with patch.dict("os.environ", {"MCP_SCANNER_API_KEY": "test_key"}):
                results = await scan_mcp_server_direct(
                    "https://test.com", [AnalyzerEnum.API], verbose=True
                )

                assert results == []
                captured = capsys.readouterr()
                assert "Connection Error" in captured.out
                assert "Troubleshooting tips" in captured.out

    @pytest.mark.asyncio
    async def test_scan_mcp_server_direct_general_exception(self, capsys):
        """Test scan_mcp_server_direct with general exception."""
        with patch("mcpscanner.cli.Scanner") as mock_scanner_class:
            mock_scanner = AsyncMock()
            mock_scanner.scan_remote_server_tools.side_effect = Exception(
                "General error"
            )
            mock_scanner_class.return_value = mock_scanner

            with patch.dict("os.environ", {"MCP_SCANNER_API_KEY": "test_key"}):
                results = await scan_mcp_server_direct(
                    "https://test.com", [AnalyzerEnum.API], verbose=True
                )

                assert results == []
                captured = capsys.readouterr()
                assert "Error scanning server" in captured.out

    @pytest.mark.asyncio
    async def test_scan_mcp_server_direct_with_endpoint_url(self, mock_scan_results):
        """Test scan_mcp_server_direct with custom endpoint URL."""
        with patch("mcpscanner.cli.Scanner") as mock_scanner_class:
            mock_scanner = AsyncMock()
            mock_scanner.scan_remote_server_tools.return_value = mock_scan_results
            mock_scanner_class.return_value = mock_scanner

            with patch("mcpscanner.cli.results_to_json") as mock_results_to_json:
                mock_results_to_json.return_value = []

                with patch.dict("os.environ", {"MCP_SCANNER_API_KEY": "test_key"}):
                    await scan_mcp_server_direct(
                        "https://test.com",
                        [AnalyzerEnum.API],
                        endpoint_url="https://custom.endpoint.com",
                    )

                    # Verify Config was created with custom endpoint
                    mock_scanner_class.assert_called_once()
                    config = mock_scanner_class.call_args[0][0]
                    assert config.base_url == "https://custom.endpoint.com"


class TestDisplayResults:
    """Test cases for display_results function."""

    @pytest.fixture
    def sample_results(self):
        """Sample scan results for testing."""
        return {
            "server_url": "https://test.com",
            "scan_results": [
                {"tool_name": "safe_tool", "is_safe": True, "findings": {}},
                {
                    "tool_name": "unsafe_tool",
                    "is_safe": False,
                    "findings": {
                        "api_analyzer": {
                            "total_findings": 2,
                            "threat_summary": "Malicious content detected",
                            "severity": "HIGH",
                            "threat_names": ["prompt_injection", "data_exfiltration"],
                        },
                        "yara_analyzer": {
                            "total_findings": 1,
                            "threat_summary": "Pattern match found",
                            "severity": "MEDIUM",
                            "threat_names": ["suspicious_pattern"],
                        },
                    },
                },
            ],
        }

    def test_display_results_basic(self, sample_results, capsys):
        """Test basic display_results functionality."""
        display_results(sample_results)

        captured = capsys.readouterr()
        assert "MCP Scanner Results" in captured.out
        assert "Server URL: https://test.com" in captured.out
        assert "Tools scanned: 2" in captured.out
        assert "Safe tools: 1" in captured.out
        assert "Unsafe tools: 1" in captured.out
        assert "unsafe_tool" in captured.out

    def test_display_results_detailed(self, sample_results, capsys):
        """Test display_results with detailed output."""
        display_results(sample_results, detailed=True)

        captured = capsys.readouterr()
        assert "Malicious content detected" in captured.out
        assert "Severity: HIGH" in captured.out
        assert "Analyzer: API" in captured.out
        assert "Threats: Prompt Injection, Data Exfiltration" in captured.out
        assert "Pattern match found" in captured.out
        assert "Analyzer: YARA" in captured.out

    def test_display_results_no_unsafe_tools(self, capsys):
        """Test display_results with no unsafe tools."""
        results = {
            "server_url": "https://test.com",
            "scan_results": [
                {"tool_name": "safe_tool", "is_safe": True, "findings": {}}
            ],
        }

        display_results(results)

        captured = capsys.readouterr()
        assert "Safe tools: 1" in captured.out
        assert "Unsafe tools: 0" in captured.out
        assert "Unsafe Tools" not in captured.out

    def test_display_results_empty_results(self, capsys):
        """Test display_results with empty scan results."""
        results = {"server_url": "https://test.com", "scan_results": []}

        display_results(results)

        captured = capsys.readouterr()
        assert "Tools scanned: 0" in captured.out
        assert "Safe tools: 0" in captured.out
        assert "Unsafe tools: 0" in captured.out

    def test_display_results_missing_fields(self, capsys):
        """Test display_results with missing fields."""
        results = {
            "scan_results": [
                {
                    "is_safe": False,
                    "findings": {"unknown_analyzer": {"total_findings": 1}},
                }
            ]
        }

        display_results(results, detailed=True)

        captured = capsys.readouterr()
        assert "Server URL: N/A" in captured.out
        assert "Unknown" in captured.out  # Tool name fallback

    def test_display_results_no_findings_in_unsafe_tool(self, capsys):
        """Test display_results with unsafe tool but no findings."""
        results = {
            "server_url": "https://test.com",
            "scan_results": [
                {"tool_name": "unsafe_tool", "is_safe": False, "findings": {}}
            ],
        }

        display_results(results)

        captured = capsys.readouterr()
        assert "unsafe_tool" in captured.out
        assert "Findings: 0" in captured.out

    def test_display_results_invalid_analyzer_data(self, capsys):
        """Test display_results with invalid analyzer data."""
        results = {
            "server_url": "https://test.com",
            "scan_results": [
                {
                    "tool_name": "unsafe_tool",
                    "is_safe": False,
                    "findings": {
                        "invalid_analyzer": "not_a_dict",
                        "valid_analyzer": {
                            "total_findings": 1,
                            "threat_summary": "Valid finding",
                            "severity": "LOW",
                        },
                    },
                }
            ],
        }

        display_results(results, detailed=True)

        captured = capsys.readouterr()
        assert "Valid finding" in captured.out
        assert "Severity: LOW" in captured.out
        # Should handle invalid analyzer gracefully
