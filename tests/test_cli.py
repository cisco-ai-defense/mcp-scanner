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
import os
import tempfile
from pathlib import Path
from unittest.mock import patch, AsyncMock, MagicMock
from typing import List, Dict, Any

from rich.panel import Panel
from rich.table import Table

from mcpscanner.cli import (
    _get_endpoint_from_env,
    _build_config,
    scan_mcp_server_direct,
    display_results,
    _build_behavioral_results,
)
from mcpscanner.core.analyzers.api_analyzer import ApiAnalyzer
from mcpscanner.core.analyzers.base import SecurityFinding
from mcpscanner import Config, ToolScanResult
from mcpscanner.core.models import AnalyzerEnum
from mcpscanner.core.exceptions import MCPConnectionError


class TestCliHelperFunctions:
    """Test cases for CLI helper functions."""

    def test_build_behavioral_results_from_findings_when_analyzed_functions_empty(
        self,
    ):
        """CLI --raw must not drop real findings when analyzed_functions is empty."""
        finding = SecurityFinding(
            severity="HIGH",
            summary="Line 1: DATA EXFILTRATION - mismatch",
            threat_category="DATA EXFILTRATION",
            analyzer="Behavioral",
            details={
                "function_name": "leaky_tool",
                "source_file": "/repo/tools.py",
                "decorator_type": "@mcp.tool",
                "line_number": 1,
            },
        )
        analyzer = MagicMock()
        analyzer.analyzed_functions = []

        results = _build_behavioral_results(
            analyzer, [finding], source_path="/repo"
        )

        assert len(results) == 1
        assert results[0]["tool_name"] == "leaky_tool"
        assert results[0]["is_safe"] is False
        behavioral = results[0]["findings"]["behavioral_analyzer"]
        assert behavioral["severity"] == "HIGH"
        assert behavioral.get("threat_vulnerability_classification") == "THREAT"

    def test_infer_classification_prefers_threat_over_vulnerability(self):
        """Non-raw THREAT filter must not drop a tool that has both classes."""
        vuln = SecurityFinding(
            severity="MEDIUM",
            summary="Vulnerability finding",
            threat_category="",
            analyzer="Behavioral",
            details={
                "function_name": "mixed_tool",
                "source_file": "/repo/tools.py",
                "threat_vulnerability_classification": "VULNERABILITY",
            },
        )
        threat = SecurityFinding(
            severity="HIGH",
            summary="Threat finding",
            threat_category="DATA EXFILTRATION",
            analyzer="Behavioral",
            details={
                "function_name": "mixed_tool",
                "source_file": "/repo/tools.py",
                "threat_vulnerability_classification": "THREAT",
            },
        )
        analyzer = MagicMock()
        analyzer.analyzed_functions = []

        results = _build_behavioral_results(
            analyzer, [vuln, threat], source_path="/repo"
        )
        assert len(results) == 1
        behavioral = results[0]["findings"]["behavioral_analyzer"]
        assert behavioral["threat_vulnerability_classification"] == "THREAT"
        assert behavioral["total_findings"] == 1
        assert behavioral["threat_summary"] == "Threat finding"
        assert behavioral["severity"] == "HIGH"

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

    def test_build_config_with_stdio_timeout(self):
        """Test _build_config passes MCP_SCANNER_STDIO_TIMEOUT to Config."""
        analyzers = [AnalyzerEnum.YARA]

        with patch.dict(
            "os.environ",
            {"MCP_SCANNER_STDIO_TIMEOUT": "180"},
        ):
            config = _build_config(analyzers)
            assert config.stdio_timeout == 180

    def test_build_config_stdio_timeout_default(self):
        """Test _build_config uses default stdio_timeout when env var is not set."""
        analyzers = [AnalyzerEnum.YARA]

        with patch.dict("os.environ", {}, clear=False):
            env = dict(**{k: v for k, v in __import__("os").environ.items()})
            env.pop("MCP_SCANNER_STDIO_TIMEOUT", None)
            with patch.dict("os.environ", env, clear=True):
                config = _build_config(analyzers)
                assert config.stdio_timeout == 60

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
    async def test_scan_mcp_server_direct_connection_error_uses_rich_panel(self):
        """Connection errors render as a real rich.panel.Panel."""
        with patch("mcpscanner.cli.Scanner") as mock_scanner_class:
            mock_scanner = AsyncMock()
            mock_scanner.scan_remote_server_tools.side_effect = MCPConnectionError(
                "Connection failed"
            )
            mock_scanner_class.return_value = mock_scanner

            with (
                patch.dict("os.environ", {"MCP_SCANNER_API_KEY": "test_key"}),
                patch("mcpscanner.cli.console.print") as mock_print,
            ):
                await scan_mcp_server_direct(
                    "https://test.com", [AnalyzerEnum.API], verbose=True
                )

                panels = [
                    call.args[0]
                    for call in mock_print.call_args_list
                    if call.args and isinstance(call.args[0], Panel)
                ]
                assert len(panels) == 1

    @pytest.mark.asyncio
    async def test_main_scan_error_uses_rich_panel_on_stderr(self, capsys):
        """main()'s own top-level scan try/except is what a real
        `mcp-scanner --server-url ...` invocation hits on a connection
        failure -- scan_mcp_server_direct has no callers outside its own
        tests, so its Panel never reaches a real user on its own. This
        must render the same Rich panel, and (matching the pre-existing
        stderr convention main() used before this PR) still write to
        stderr, not stdout."""
        from mcpscanner.cli import main

        with patch("mcpscanner.cli.Scanner") as mock_scanner_class:
            mock_scanner = AsyncMock()
            mock_scanner.scan_remote_server_tools.side_effect = MCPConnectionError(
                "Connection failed"
            )
            mock_scanner_class.return_value = mock_scanner

            test_args = [
                "mcp-scanner",
                "--analyzers",
                "yara",
                "--server-url",
                "https://test.com",
            ]
            with (
                patch("sys.argv", test_args),
                patch.dict("os.environ", {"MCP_SCANNER_API_KEY": "test_key"}),
            ):
                with pytest.raises(SystemExit):
                    await main()

                captured = capsys.readouterr()
                assert captured.out == ""
                assert "Connection Error" in captured.err
                assert "Connection failed" in captured.err

    @pytest.mark.asyncio
    async def test_main_scan_error_panel_does_not_crop_long_messages(self, capsys):
        """The shared console's soft_wrap=True is for plain text and table
        cells (don't force a line break). Panel enforces a fixed width and
        can't let content overflow its border, so with soft wrapping on,
        Rich crops the message after the first line instead of wrapping
        it -- silently dropping everything past that point. The end of a
        long message is what proves this: a test that only checks the
        message is "present somewhere" in the output still passes even
        when most of it got cropped off."""
        from mcpscanner.cli import main

        long_message = (
            "Connection to MCP server at "
            + "http://127.0.0.1:9/mcp/" + "segment" * 10
            + " was cancelled. This may indicate the server is not "
            "reachable, not responding, or requires authentication."
        )

        with patch("mcpscanner.cli.Scanner") as mock_scanner_class:
            mock_scanner = AsyncMock()
            mock_scanner.scan_remote_server_tools.side_effect = MCPConnectionError(
                long_message
            )
            mock_scanner_class.return_value = mock_scanner

            test_args = [
                "mcp-scanner",
                "--analyzers",
                "yara",
                "--server-url",
                "https://test.com",
            ]
            with (
                patch("sys.argv", test_args),
                patch.dict("os.environ", {"MCP_SCANNER_API_KEY": "test_key"}),
            ):
                with pytest.raises(SystemExit):
                    await main()

                captured = capsys.readouterr()
                assert "requires authentication." in captured.err

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

    def test_display_results_unsafe_tools_use_rich_table(self, sample_results):
        """The unsafe-tools summary must be a real rich.table.Table, not a
        styled string -- this is what distinguishes the Rich UX from just
        adding ANSI color codes to the old print() calls."""
        with patch("mcpscanner.cli.console.print") as mock_print:
            display_results(sample_results)

            tables = [
                call.args[0]
                for call in mock_print.call_args_list
                if call.args and isinstance(call.args[0], Table)
            ]
            assert len(tables) == 1
            columns = [col.header for col in tables[0].columns]
            assert columns == ["#", "Tool", "Findings"]
            # Table.rows holds Row objects with no .cells attribute in Rich
            # 13.7.0; cell values live on each column instead. The fixture
            # has two API findings and one YARA finding -> 3 total.
            assert [list(column.cells) for column in tables[0].columns] == [
                ["1"],
                ["unsafe_tool"],
                ["3"],
            ]

    def test_display_results_escapes_rich_markup_in_tool_name(self, capsys):
        """A server-controlled tool name containing Rich markup syntax must
        not be interpreted as formatting -- an unmatched closing tag like
        `[/red]` would otherwise raise MarkupError and cut the report short
        before later findings are rendered, and valid markup could forge
        styling in the terminal output."""
        results = {
            "server_url": "https://test.com",
            "scan_results": [
                {
                    "tool_name": "evil[/red][bold]tool",
                    "is_safe": False,
                    "findings": {},
                }
            ],
        }

        # Must not raise MarkupError, and the literal brackets must survive
        # into the rendered output rather than being swallowed as markup.
        display_results(results)

        captured = capsys.readouterr()
        assert "evil[/red][bold]tool" in captured.out

    def test_display_results_does_not_convert_emoji_shortcodes(self, capsys):
        """rich.markup.escape() only escapes `[...]` markup, not `:name:`
        emoji shortcodes -- Rich still converts those by default. A
        server-controlled tool name containing a shortcode must display as
        the literal text, not the emoji glyph: the glyph is a different
        string than what the server actually sent, and on some terminals
        (observed: Windows legacy console codepage) isn't even encodable,
        crashing the write entirely."""
        results = {
            "server_url": "https://test.com",
            "scan_results": [
                {
                    "tool_name": "exfil:warning:tool",
                    "is_safe": False,
                    "findings": {},
                }
            ],
        }

        display_results(results)

        captured = capsys.readouterr()
        assert "exfil:warning:tool" in captured.out
        assert "⚠" not in captured.out

    def test_display_results_does_not_hard_wrap_long_lines(self, capsys):
        """A threat summary or URL is an indicator a user may grep or copy
        out of CI logs. Rich's default hard-wraps long lines at the console
        width, splitting an indicator across multiple lines in piped
        output and breaking exactly that grep/copy use case."""
        long_summary = "Exfiltrates data to http://evil.example.com/" + "a" * 150
        results = {
            "server_url": "https://test.com",
            "scan_results": [
                {
                    "tool_name": "unsafe_tool",
                    "is_safe": False,
                    "findings": {
                        "api_analyzer": {
                            "total_findings": 1,
                            "threat_summary": long_summary,
                            "severity": "HIGH",
                        }
                    },
                }
            ],
        }

        display_results(results, detailed=True)

        captured = capsys.readouterr()
        assert long_summary in captured.out

    def test_display_results_no_table_when_no_unsafe_tools(self):
        """No unsafe tools means nothing to summarize in a table."""
        results = {
            "server_url": "https://test.com",
            "scan_results": [
                {"tool_name": "safe_tool", "is_safe": True, "findings": {}}
            ],
        }
        with patch("mcpscanner.cli.console.print") as mock_print:
            display_results(results)

            tables = [
                call.args[0]
                for call in mock_print.call_args_list
                if call.args and isinstance(call.args[0], Table)
            ]
            assert tables == []


class TestStaticSubcommandCLI:
    """Test cases for the static subcommand CLI integration."""

    @pytest.fixture
    def tools_json_file(self, tmp_path):
        """Create a temporary tools JSON file."""
        tools_data = {
            "tools": [
                {
                    "name": "test_tool",
                    "description": "A test tool",
                    "inputSchema": {"type": "object"},
                }
            ]
        }
        file_path = tmp_path / "tools.json"
        with open(file_path, "w") as f:
            json.dump(tools_data, f)
        return str(file_path)

    @pytest.fixture
    def prompts_json_file(self, tmp_path):
        """Create a temporary prompts JSON file."""
        prompts_data = {
            "prompts": [
                {"name": "test_prompt", "description": "A test prompt", "arguments": []}
            ]
        }
        file_path = tmp_path / "prompts.json"
        with open(file_path, "w") as f:
            json.dump(prompts_data, f)
        return str(file_path)

    @pytest.fixture
    def resources_json_file(self, tmp_path):
        """Create a temporary resources JSON file."""
        resources_data = {
            "resources": [
                {
                    "uri": "file:///test/resource.txt",
                    "name": "test_resource",
                    "description": "A test resource",
                    "mimeType": "text/plain",
                    "text": "actual resource body for the canonical shape pin",
                }
            ]
        }
        file_path = tmp_path / "resources.json"
        with open(file_path, "w") as f:
            json.dump(resources_data, f)
        return str(file_path)

    @pytest.mark.asyncio
    async def test_static_tools_scan_success(self, tools_json_file, capsys):
        """Test static subcommand with tools file."""
        from mcpscanner.cli import main

        test_args = [
            "mcp-scanner",
            "--analyzers",
            "yara",
            "static",
            "--tools",
            tools_json_file,
        ]

        with patch("sys.argv", test_args):
            await main()

            captured = capsys.readouterr()
            assert "MCP Scanner Results" in captured.out
            assert "Total tools scanned: 1" in captured.out
            assert "Safe items: 1" in captured.out

    @pytest.mark.asyncio
    async def test_api_key_flag_is_applied_before_static_dispatch(
        self, tools_json_file, monkeypatch, capsys
    ):
        """Global CLI environment overrides are applied before subcommand dispatch."""
        from mcpscanner.cli import main

        monkeypatch.delenv("MCP_SCANNER_API_KEY", raising=False)
        api_keys_seen_at_config_time = []

        def spy_build_config(selected_analyzers, endpoint_url=None):
            api_keys_seen_at_config_time.append(
                os.environ.get("MCP_SCANNER_API_KEY", "")
            )
            return _build_config(selected_analyzers, endpoint_url)

        test_args = [
            "mcp-scanner",
            "--api-key",
            "test-api-key",
            "--analyzers",
            "api",
            "static",
            "--tools",
            tools_json_file,
        ]

        with patch(
            "mcpscanner.cli._build_config", side_effect=spy_build_config
        ), patch.object(
            ApiAnalyzer, "analyze", new_callable=AsyncMock
        ) as mock_analyze:
            mock_analyze.return_value = []
            with patch("sys.argv", test_args):
                await main()

        assert api_keys_seen_at_config_time == ["test-api-key"]
        assert mock_analyze.await_count >= 1
        assert "MCP Scanner Results" in capsys.readouterr().out
        assert os.environ["MCP_SCANNER_API_KEY"] == "test-api-key"

    @pytest.mark.asyncio
    async def test_static_resources_result_conversion(self, resources_json_file):
        """Test that resources from static scan are correctly converted to ResourceScanResult."""
        from mcpscanner.core.analyzers.static_analyzer import StaticAnalyzer
        from mcpscanner.core.analyzers.yara_analyzer import YaraAnalyzer
        from mcpscanner.core.result import ResourceScanResult

        analyzer = StaticAnalyzer(analyzers=[YaraAnalyzer()])
        results = await analyzer.scan_resources_file(resources_json_file)

        assert len(results) == 1
        r = results[0]

        # Verify we can create a ResourceScanResult - this is what CLI does.
        # Mirror the CLI's actual call site (mcpscanner/cli.py): the static
        # path now threads ``resource_description`` and ``resource_text``
        # through so ``--enable-meta`` can second-guess the same evidence
        # the primary analyzers consumed.
        resource_result = ResourceScanResult(
            resource_uri=r["resource_uri"],
            resource_name=r["resource_name"],
            resource_mime_type=r.get("resource_mime_type", "unknown"),
            status=r["status"],
            analyzers=r.get("analyzers", []),
            findings=r["findings"],
            resource_description=r.get("resource_description", ""),
            resource_text=r.get("resource_text", ""),
        )

        assert resource_result.resource_uri == "file:///test/resource.txt"
        assert resource_result.resource_name == "test_resource"
        assert resource_result.status == "completed"
        # P0-3 + P1-1 canonical-shape pin: ``resource_description`` holds
        # the MCP description verbatim, ``resource_text`` holds the
        # resource BODY only (no LLM-formatted preamble, no description
        # duplication, no URI/name/MIME header leak).
        assert resource_result.resource_description == "A test resource"
        assert (
            resource_result.resource_text
            == "actual resource body for the canonical shape pin"
        )
        assert "Resource URI:" not in resource_result.resource_text
        assert "Description: A test resource" not in resource_result.resource_text
        assert "MIME Type:" not in resource_result.resource_text

    @pytest.mark.asyncio
    async def test_static_prompts_scan(self, prompts_json_file, capsys):
        """Test static subcommand with prompts file only."""
        from mcpscanner.cli import main

        test_args = [
            "mcp-scanner",
            "--analyzers",
            "yara",
            "static",
            "--prompts",
            prompts_json_file,
        ]

        with patch("sys.argv", test_args):
            await main()

            captured = capsys.readouterr()
            assert "MCP Scanner Results" in captured.out
            # Static subcommand uses unified output format - prompts appear as scanned items
            assert "Total tools scanned: 1" in captured.out
            assert "Safe items: 1" in captured.out

    @pytest.mark.asyncio
    async def test_static_no_files_specified(self, capsys):
        """Test static subcommand with no files specified."""
        from mcpscanner.cli import main

        test_args = ["mcp-scanner", "--analyzers", "yara", "static"]

        with patch("sys.argv", test_args):
            with pytest.raises(SystemExit) as exc_info:
                await main()

            assert exc_info.value.code == 1
            captured = capsys.readouterr()
            assert "No files specified" in captured.err

    @pytest.mark.asyncio
    async def test_static_file_not_found(self, capsys):
        """Test static subcommand with non-existent file."""
        from mcpscanner.cli import main

        test_args = [
            "mcp-scanner",
            "--analyzers",
            "yara",
            "static",
            "--tools",
            "/nonexistent/tools.json",
        ]

        with patch("sys.argv", test_args):
            with pytest.raises(SystemExit):
                await main()

            captured = capsys.readouterr()
            assert "Error" in captured.err or "not found" in captured.err.lower()

    @pytest.mark.asyncio
    async def test_static_with_mime_type_filter(self, resources_json_file, capsys):
        """Test static subcommand with MIME type filtering for resources."""
        from mcpscanner.cli import main

        test_args = [
            "mcp-scanner",
            "--analyzers",
            "yara",
            "static",
            "--resources",
            resources_json_file,
            "--mime-types",
            "text/plain,text/html",
        ]

        with patch("sys.argv", test_args):
            await main()

            captured = capsys.readouterr()
            assert "MCP Scanner Results" in captured.out
            # Static subcommand uses unified output format - resources appear as scanned items
            assert "Total tools scanned: 1" in captured.out
            assert "Safe items: 1" in captured.out


class TestMainGlobalEnvFlags:
    """Regression tests for issue #251.

    A local ``import os`` inside the ``vulnerable-package`` branch of
    ``main()`` made ``os`` function-local for the whole of ``main()``, so
    every global flag that writes ``os.environ`` (e.g. ``--api-key``) crashed
    with ``UnboundLocalError`` before the local import was ever reached.
    """

    @pytest.fixture
    def issue_251_tools_file(self, tmp_path):
        """Create a temporary tools JSON file for the static subcommand."""
        tools_data = {
            "tools": [
                {
                    "name": "test_tool",
                    "description": "A test tool",
                    "inputSchema": {"type": "object"},
                }
            ]
        }
        file_path = tmp_path / "tools.json"
        with open(file_path, "w") as f:
            json.dump(tools_data, f)
        return str(file_path)

    @staticmethod
    def _shadowed_module_imports():
        """Module-level import names that ``main()`` rebinds with a local
        ``import`` placed after their first use in ``main()``.

        Returns a dict of ``name -> (module_import_line, local_import_line,
        first_use_line)``. Any entry here is an ``UnboundLocalError`` waiting
        to happen for every use before the local import.
        """
        import ast
        from pathlib import Path

        cli_path = Path(__file__).resolve().parent.parent / "mcpscanner" / "cli.py"
        tree = ast.parse(cli_path.read_text())

        def imported_names(nodes):
            names = {}
            for node in nodes:
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        names[alias.asname or alias.name.split(".")[0]] = node.lineno
                elif isinstance(node, ast.ImportFrom):
                    for alias in node.names:
                        names[alias.asname or alias.name] = node.lineno
            return names

        module_imports = imported_names(tree.body)
        main_fn = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.AsyncFunctionDef) and node.name == "main"
        )
        local_imports = imported_names(ast.walk(main_fn))
        first_use = {}
        for node in ast.walk(main_fn):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                first_use.setdefault(node.id, node.lineno)

        return {
            name: (module_imports[name], local_imports[name], first_use[name])
            for name in local_imports
            if name in module_imports
            and name in first_use
            and first_use[name] < local_imports[name]
        }

    def test_main_does_not_shadow_module_imports(self):
        """No local import inside main() may shadow a module-level name that
        main() already uses (issue #251)."""
        shadowed = self._shadowed_module_imports()
        assert not shadowed, (
            "main() locally re-imports module-level names after their first "
            f"use, making them unbound locals: {shadowed}"
        )

    @pytest.mark.asyncio
    async def test_api_key_flag_does_not_raise_unbound_local_error(
        self, issue_251_tools_file, capsys, monkeypatch
    ):
        """End-to-end repro of #251: ``--api-key`` must set the env var and
        the scan must proceed instead of raising ``UnboundLocalError``."""
        import os

        from mcpscanner.cli import main

        monkeypatch.setenv("MCP_SCANNER_API_KEY", "")
        monkeypatch.delenv("MCP_SCANNER_API_KEY", raising=False)
        test_args = [
            "mcp-scanner",
            "--api-key",
            "test-key-251",
            "--analyzers",
            "yara",
            "static",
            "--tools",
            issue_251_tools_file,
        ]
        with patch("sys.argv", test_args):
            await main()

        captured = capsys.readouterr()
        assert "UnboundLocalError" not in captured.out
        assert "UnboundLocalError" not in captured.err
        assert os.environ.get("MCP_SCANNER_API_KEY") == "test-key-251"
        assert "Total tools scanned: 1" in captured.out


class TestStderrFileConfigScans:
    """--stderr-file must reach the stdio servers spawned by config scans."""

    @pytest.fixture
    def config_file(self, tmp_path):
        path = tmp_path / "mcp.json"
        path.write_text(json.dumps({"mcpServers": {}}))
        return str(path)

    @staticmethod
    async def _run_main(argv, method_name, return_value):
        from mcpscanner.cli import main

        calls = []

        async def fake_scan(*args, **kwargs):
            errlog = kwargs.get("errlog")
            calls.append(errlog)
            if errlog is not None:
                errlog.write("server banner\n")
            return return_value

        with patch("mcpscanner.cli.Scanner") as mock_scanner_class:
            mock_scanner = AsyncMock()
            setattr(mock_scanner, method_name, AsyncMock(side_effect=fake_scan))
            mock_scanner_class.return_value = mock_scanner
            with patch("sys.argv", ["mcp-scanner", "--analyzers", "yara", *argv]):
                await main()

        assert len(calls) == 1
        return calls[0]

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "argv_template",
        [
            ["config", "--config-path", "{cfg}", "--stderr-file", "{log}"],
            ["--stderr-file", "{log}", "config", "--config-path", "{cfg}"],
            ["--config-path", "{cfg}", "--stderr-file", "{log}"],
        ],
        ids=["subcommand", "top-level-flag-before-subcommand", "legacy"],
    )
    async def test_config_file_scan_uses_stderr_file(
        self, argv_template, config_file, tmp_path
    ):
        log = tmp_path / "server-stderr.log"
        argv = [a.format(cfg=config_file, log=log) for a in argv_template]

        errlog = await self._run_main(argv, "scan_mcp_config_file", [])

        assert errlog is not None
        assert errlog.name == str(log)
        assert errlog.closed
        assert log.read_text() == "server banner\n"

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "argv_template",
        [
            ["known-configs", "--stderr-file", "{log}"],
            ["--stderr-file", "{log}", "known-configs"],
            ["--scan-known-configs", "--stderr-file", "{log}"],
        ],
        ids=["subcommand", "top-level-flag-before-subcommand", "legacy"],
    )
    async def test_known_configs_scan_uses_stderr_file(self, argv_template, tmp_path):
        log = tmp_path / "server-stderr.log"
        argv = [a.format(log=log) for a in argv_template]

        errlog = await self._run_main(argv, "scan_well_known_mcp_configs", {})

        assert errlog is not None
        assert errlog.name == str(log)
        assert errlog.closed
        assert log.read_text() == "server banner\n"

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "argv, method_name, return_value",
        [
            (["config", "--config-path", "{cfg}"], "scan_mcp_config_file", []),
            (["known-configs"], "scan_well_known_mcp_configs", {}),
            (["--scan-known-configs"], "scan_well_known_mcp_configs", {}),
        ],
        ids=["config", "known-configs", "legacy-known-configs"],
    )
    async def test_config_scans_default_to_no_errlog(
        self, argv, method_name, return_value, config_file
    ):
        argv = [a.format(cfg=config_file) for a in argv]

        errlog = await self._run_main(argv, method_name, return_value)

        assert errlog is None


class TestStderrFileStdioSubcommand:
    """A top-level --stderr-file must survive the stdio subparser default."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "argv_template",
        [
            ["--stderr-file", "{log}", "stdio", "--stdio-command", "python"],
            ["stdio", "--stdio-command", "python", "--stderr-file", "{log}"],
        ],
        ids=["top-level-flag-before-subcommand", "subcommand"],
    )
    async def test_stdio_subcommand_keeps_stderr_file(self, argv_template, tmp_path):
        log = tmp_path / "server-stderr.log"
        argv = [a.format(log=log) for a in argv_template]

        errlog = await TestStderrFileConfigScans._run_main(
            argv, "scan_stdio_server_tools", []
        )

        assert errlog is not None
        assert errlog.name == str(log)
        assert errlog.closed
        assert log.read_text() == "server banner\n"

    @pytest.mark.asyncio
    async def test_stdio_subcommand_without_flag_passes_no_errlog(self):
        errlog = await TestStderrFileConfigScans._run_main(
            ["stdio", "--stdio-command", "python"],
            "scan_stdio_server_tools",
            [],
        )

        assert errlog is None
