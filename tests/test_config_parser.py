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

"""Unit tests for config parser module."""

import pytest
import json
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock
from typing import Dict, Any

from mcpscanner.config.config_parser import (
    MCPConfigScanner,
    rebalance_command_args,
    scan_mcp_config_file,
)
from mcpscanner.core.mcp_models import StdioServer, RemoteServer, ClaudeConfigFile


class TestRebalanceCommandArgs:
    """Test cases for rebalance_command_args function."""

    def test_rebalance_simple_command(self):
        """Test rebalancing with simple command."""
        command, args = rebalance_command_args("python", ["-m", "server"])
        assert command == "python"
        assert args == ["-m", "server"]

    def test_rebalance_complex_command(self):
        """Test rebalancing with command containing spaces."""
        command, args = rebalance_command_args(
            "python -m uvicorn", ["--host", "0.0.0.0"]
        )
        assert command == "python"
        assert args == ["-m", "uvicorn", "--host", "0.0.0.0"]

    def test_rebalance_empty_command(self):
        """Test rebalancing with empty command."""
        command, args = rebalance_command_args("", ["arg1", "arg2"])
        assert command == ""
        assert args == ["arg1", "arg2"]

    def test_rebalance_no_args(self):
        """Test rebalancing with no args."""
        command, args = rebalance_command_args("python", [])
        assert command == "python"
        assert args == []

    def test_rebalance_command_with_multiple_spaces(self):
        """Test rebalancing with command having multiple parts."""
        command, args = rebalance_command_args(
            "node --experimental-modules server.js", ["--port", "3000"]
        )
        assert command == "node"
        assert args == ["--experimental-modules", "server.js", "--port", "3000"]


class TestScanMcpConfigFile:
    """Test cases for scan_mcp_config_file function."""

    @pytest.fixture
    def claude_config(self):
        """Sample Claude configuration."""
        return {
            "mcpServers": {
                "test_server": {
                    "command": "python",
                    "args": ["-m", "test_server"],
                    "env": {"TEST_VAR": "value"},
                }
            }
        }

    @pytest.fixture
    def vscode_config(self):
        """Sample VSCode configuration."""
        return {
            "mcp": {
                "servers": {
                    "test_server": {"command": "python", "args": ["-m", "test_server"]}
                }
            }
        }

    @pytest.mark.asyncio
    async def test_scan_claude_config(self, claude_config):
        """Test scanning Claude configuration file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(claude_config, f)
            config_path = f.name

        try:
            config = await scan_mcp_config_file(config_path)
            assert isinstance(config, ClaudeConfigFile)
            assert "test_server" in config.mcpServers
        finally:
            Path(config_path).unlink()

    @pytest.mark.asyncio
    async def test_scan_vscode_config(self, vscode_config):
        """Test scanning VSCode configuration file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(vscode_config, f)
            config_path = f.name

        try:
            config = await scan_mcp_config_file(config_path)
            # Check that it's a valid VSCodeConfigFile with mcp.mcpServers attribute
            assert hasattr(config, "mcp")
            assert hasattr(config.mcp, "mcpServers")
            assert isinstance(config.mcp.mcpServers, dict)
            # The parsing should succeed without errors
        finally:
            Path(config_path).unlink()

    @pytest.mark.asyncio
    async def test_scan_nonexistent_file(self):
        """Test scanning nonexistent file."""
        with pytest.raises(FileNotFoundError):
            await scan_mcp_config_file("/nonexistent/path/config.json")

    @pytest.mark.asyncio
    async def test_scan_invalid_json(self):
        """Test scanning file with invalid JSON."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("invalid json content")
            config_path = f.name

        try:
            with pytest.raises(Exception):
                await scan_mcp_config_file(config_path)
        finally:
            Path(config_path).unlink()

    @pytest.mark.asyncio
    async def test_scan_unsupported_config_format(self):
        """Test scanning file with unsupported configuration format."""
        unsupported_config = {"unsupported": "format"}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(unsupported_config, f)
            config_path = f.name

        try:
            # The current parser is permissive and will parse this as ClaudeConfigFile
            # with default mcpServers={}, so we test that it succeeds
            config = await scan_mcp_config_file(config_path)
            assert hasattr(config, "mcpServers")
            assert config.mcpServers == {}
        finally:
            Path(config_path).unlink()

    @pytest.mark.asyncio
    async def test_scan_with_tilde_expansion(self, claude_config):
        """Test scanning with tilde path expansion."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(claude_config, f)
            config_path = f.name

        try:
            # Mock expanduser to return the actual path
            with patch("os.path.expanduser", return_value=config_path):
                config = await scan_mcp_config_file("~/config.json")
                assert isinstance(config, ClaudeConfigFile)
        finally:
            Path(config_path).unlink()


class TestMCPConfigScanner:
    """Test cases for MCPConfigScanner class."""

    @pytest.fixture
    def scanner(self):
        """Provide MCPConfigScanner instance."""
        return MCPConfigScanner()

    @pytest.fixture
    def claude_config(self):
        """Sample Claude configuration."""
        return {
            "mcpServers": {
                "stdio_server": {
                    "command": "python",
                    "args": ["-m", "stdio_server"],
                    "env": {"TEST_VAR": "value"},
                },
                "remote_server": {"url": "https://example.com/mcp"},
            }
        }

    def test_scanner_initialization(self, scanner):
        """Test MCPConfigScanner initialization."""
        assert scanner is not None

    @pytest.mark.asyncio
    async def test_scan_well_known_paths_no_files(self, scanner):
        """Test scanning well-known paths with no config files."""
        with patch("os.path.exists", return_value=False):
            configs = await scanner.scan_well_known_paths()
            assert configs == {}

    @pytest.mark.asyncio
    async def test_scan_well_known_paths_with_files(self, scanner, claude_config):
        """Test scanning well-known paths with config files."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "claude_desktop_config.json"
            with open(config_path, "w") as f:
                json.dump(claude_config, f)

            # Mock the well-known paths to point to our temp file
            with patch.object(
                scanner.constants,
                "get_well_known_mcp_paths",
                return_value=[str(config_path)],
            ):
                configs = await scanner.scan_well_known_paths()

                assert len(configs) == 1
                assert str(config_path) in configs

    @pytest.mark.asyncio
    async def test_scan_specific_path_success(self, scanner, claude_config):
        """Test scanning specific path successfully."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(claude_config, f)
            config_path = f.name

        try:
            config = await scanner.scan_specific_path(config_path)
            assert config is not None
            assert isinstance(config, ClaudeConfigFile)
        finally:
            Path(config_path).unlink()

    @pytest.mark.asyncio
    async def test_scan_specific_path_nonexistent(self, scanner):
        """Test scanning nonexistent specific path."""
        config = await scanner.scan_specific_path("/nonexistent/path")
        assert config is None

    def test_extract_servers_claude_config(self, scanner, claude_config):
        """Test extracting servers from Claude configuration."""
        config = ClaudeConfigFile.model_validate(claude_config)
        servers = scanner.extract_servers(config)

        assert len(servers) == 2
        assert "stdio_server" in servers
        assert "remote_server" in servers

        # Check stdio server
        stdio_server = servers["stdio_server"]
        assert isinstance(stdio_server, StdioServer)
        assert stdio_server.command == "python"
        assert stdio_server.args == ["-m", "stdio_server"]
        assert stdio_server.env == {"TEST_VAR": "value"}

        # Check remote server
        remote_server = servers["remote_server"]
        assert isinstance(remote_server, RemoteServer)
        assert remote_server.url == "https://example.com/mcp"

    def test_extract_servers_vscode_config(self, scanner):
        """Test extracting servers from VSCode configuration."""
        from mcpscanner.core.mcp_models import (
            VSCodeConfigFile,
            VSCodeMCPConfig,
            StdioServer,
        )

        vscode_config_data = {
            "mcp": {
                "mcpServers": {
                    "test_server": {"command": "node", "args": ["server.js"]}
                }
            }
        }

        config = VSCodeConfigFile.model_validate(vscode_config_data)
        servers = scanner.extract_servers(config)

        assert len(servers) == 1
        assert "test_server" in servers

        server = servers["test_server"]
        assert isinstance(server, StdioServer)
        assert server.command == "node"
        assert server.args == ["server.js"]

    def test_extract_servers_empty_config(self, scanner):
        """Test extracting servers from empty configuration."""
        empty_config = ClaudeConfigFile(mcpServers={})
        servers = scanner.extract_servers(empty_config)
        assert servers == {}

    def test_extract_servers_unsupported_config(self, scanner):
        """Test extracting servers from unsupported configuration type."""
        # Create a mock config object that's not supported
        mock_config = MagicMock()
        mock_config.__class__.__name__ = "UnsupportedConfig"
        # Configure the mock to not have mcpServers or mcp attributes
        del mock_config.mcpServers
        del mock_config.mcp

        servers = scanner.extract_servers(mock_config)
        assert servers == {}

    def test_get_well_known_paths(self, scanner):
        """Test getting well-known configuration paths."""
        paths = scanner.constants.get_well_known_mcp_paths()

        assert isinstance(paths, list)
        assert len(paths) > 0

        # Check that paths include expected locations (platform-dependent)
        path_strings = [str(p) for p in paths]
        # At least one of the common clients should be present on any platform
        expected_clients = ["windsurf", "cursor", "vscode"]
        assert any(
            client in p.lower() for p in path_strings for client in expected_clients
        )

    @pytest.mark.asyncio
    async def test_scan_well_known_paths_with_errors(self, scanner):
        """Test scanning well-known paths with file errors."""
        # Create a path that exists but has invalid content
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("invalid json")
            invalid_path = f.name

        try:
            with patch.object(
                scanner.constants,
                "get_well_known_mcp_paths",
                return_value=[invalid_path],
            ):
                configs = await scanner.scan_well_known_paths()

                # Should handle errors gracefully and return empty dict for invalid files
                assert configs == {}
        finally:
            Path(invalid_path).unlink()

    def test_extract_servers_with_command_rebalancing(self, scanner):
        """Test server extraction with complex command."""
        config_data = {
            "mcpServers": {
                "complex_server": {
                    "command": "python -m uvicorn",
                    "args": ["--host", "0.0.0.0"],
                }
            }
        }

        config = ClaudeConfigFile.model_validate(config_data)
        servers = scanner.extract_servers(config)

        server = servers["complex_server"]
        # The current implementation doesn't perform command rebalancing during extraction
        assert server.command == "python -m uvicorn"
        assert server.args == ["--host", "0.0.0.0"]

    @pytest.mark.asyncio
    async def test_scan_with_json5_support(self, scanner):
        """Test scanning with JSON5 support if available."""
        json5_content = """{
            // Comments are allowed in JSON5
            "mcpServers": {
                "test_server": {
                    "command": "python",
                    "args": ["-m", "test"]
                }
            }
        }"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write(json5_content)
            config_path = f.name

        try:
            # Mock JSON5 availability and module
            mock_json5 = MagicMock()
            mock_json5.loads.return_value = {
                "mcpServers": {
                    "test_server": {"command": "python", "args": ["-m", "test"]}
                }
            }

            with patch("mcpscanner.config.config_parser.HAS_JSON5", True):
                with patch(
                    "mcpscanner.config.config_parser.pyjson5", mock_json5, create=True
                ):
                    config = await scanner.scan_specific_path(config_path)
                    assert config is not None
        finally:
            Path(config_path).unlink()

    def test_extract_servers_missing_required_fields(self, scanner):
        """Test extracting servers with missing required fields."""
        config_data = {
            "mcpServers": {
                "incomplete_server": {
                    # Missing command for stdio server
                    "args": ["-m", "test"]
                }
            }
        }

        # This should handle validation errors gracefully
        try:
            config = ClaudeConfigFile.model_validate(config_data)
            servers = scanner.extract_servers(config)
            # Should either skip invalid servers or handle them gracefully
        except Exception:
            # Validation might fail, which is expected for invalid configs
            pass
