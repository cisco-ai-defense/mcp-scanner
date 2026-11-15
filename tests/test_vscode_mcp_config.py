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

"""VS Code MCP configs: the dotted settings key, the fields servers launch
with (cwd, headers), VS Code variables, and the Insiders/VSCodium profiles."""

import json
import os
from unittest.mock import AsyncMock, patch

import pytest

from mcpscanner import Config
from mcpscanner.config.config_parser import MCPConfigScanner, scan_mcp_config_file
from mcpscanner.core.auth import Auth, AuthType
from mcpscanner.core.mcp_models import StdioServer
from mcpscanner.core.models import AnalyzerEnum
from mcpscanner.core.scanner import Scanner, _auth_with_config_headers


def _write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data))
    return str(path)


async def _scan(config_path):
    """Run Scanner.scan_mcp_config_file and return the mocked scan calls."""
    scanner = Scanner(Config())
    with (
        patch.object(
            Scanner, "scan_stdio_server_tools", new=AsyncMock(return_value=[])
        ) as stdio,
        patch.object(
            Scanner, "scan_remote_server_tools", new=AsyncMock(return_value=[])
        ) as remote,
    ):
        await scanner.scan_mcp_config_file(config_path, analyzers=[AnalyzerEnum.YARA])
    return stdio, remote


@pytest.mark.asyncio
async def test_settings_json_dotted_mcp_servers_key(tmp_path):
    path = _write(
        tmp_path / "settings.json",
        {
            "editor.fontSize": 14,
            "mcp.servers": {
                "local": {"command": "echo", "args": ["hi"]},
                "remote": {"type": "http", "url": "https://example.com/mcp"},
            },
        },
    )
    servers = MCPConfigScanner().extract_servers(await scan_mcp_config_file(path))
    assert sorted(servers) == ["local", "remote"]
    assert servers["local"].command == "echo"
    assert servers["remote"].url == "https://example.com/mcp"


@pytest.mark.asyncio
async def test_workspace_mcp_json_reaches_the_scan_as_vs_code_launches_it(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("MCP_TEST_TOKEN", "s3cret")
    monkeypatch.delenv("MCP_TEST_UNSET", raising=False)
    workspace = tmp_path / "proj"
    path = _write(
        workspace / ".vscode" / "mcp.json",
        {
            "inputs": [{"id": "token", "type": "promptString", "password": True}],
            "servers": {
                "local": {
                    "command": "node",
                    "args": ["${workspaceFolder}${/}server.js", "--name"],
                    "cwd": "${workspaceFolder}/tools",
                    "env": {
                        "TOKEN": "${env:MCP_TEST_TOKEN}",
                        "UNSET": "${env:MCP_TEST_UNSET}",
                        "PROJECT": "${workspaceFolderBasename}",
                    },
                },
                "remote": {
                    "type": "http",
                    "url": "https://example.com/mcp",
                    "headers": {"Authorization": "Bearer ${env:MCP_TEST_TOKEN}"},
                },
                "prompted": {
                    "type": "http",
                    "url": "https://example.com/other",
                    "headers": {
                        "Authorization": "Bearer ${input:token}",
                        "X-Client": "scanner",
                    },
                },
                "prompted-arg": {
                    "command": "node",
                    "args": ["--key", "${input:token}"],
                },
            },
        },
    )

    with patch("mcpscanner.config.config_parser.logger") as log:
        stdio, remote = await _scan(path)
    warnings = " ".join(str(c.args[0]) for c in log.warning.call_args_list)

    assert stdio.call_count == 1
    server = stdio.call_args.args[0]
    assert server.args == [f"{workspace}{os.sep}server.js", "--name"]
    assert server.cwd == f"{workspace}/tools"
    assert server.env == {"TOKEN": "s3cret", "UNSET": "", "PROJECT": "proj"}

    # ${input:...} needs VS Code to prompt. In a header the header is left
    # out rather than sent as literal text; in args the server is skipped.
    calls = {c.args[0]: c.kwargs["auth"] for c in remote.call_args_list}
    assert sorted(calls) == ["https://example.com/mcp", "https://example.com/other"]
    assert calls["https://example.com/mcp"].custom_headers == {
        "Authorization": "Bearer s3cret"
    }
    assert calls["https://example.com/other"].custom_headers == {"X-Client": "scanner"}
    assert "leaving out headers 'Authorization'" in warnings
    assert "Skipping server 'prompted-arg'" in warnings
    assert "${input:token}" in warnings


@pytest.mark.asyncio
async def test_workspace_folder_in_a_user_profile_config_skips_the_server(
    tmp_path,
):
    path = _write(
        tmp_path / "Code" / "User" / "mcp.json",
        {
            "servers": {
                "needs-workspace": {"command": "${workspaceFolder}/bin/server"},
                "plain": {"command": "echo"},
            }
        },
    )
    with patch("mcpscanner.config.config_parser.logger") as log:
        stdio, _ = await _scan(path)
    assert [c.args[0].command for c in stdio.call_args_list] == ["echo"]
    warnings = " ".join(str(c.args[0]) for c in log.warning.call_args_list)
    assert "Skipping server 'needs-workspace'" in warnings


@pytest.mark.asyncio
async def test_claude_style_configs_keep_their_text_as_is(tmp_path):
    """Variable resolution only applies to the VS Code formats."""
    path = _write(
        tmp_path / "claude.json",
        {"mcpServers": {"s": {"command": "echo", "args": ["${input:x}"]}}},
    )
    stdio, _ = await _scan(path)
    assert stdio.call_args.args[0].args == ["${input:x}"]


def test_config_headers_are_used_without_explicit_auth():
    auth = _auth_with_config_headers(None, {"X-Api-Key": "k"})
    assert auth.custom_headers == {"X-Api-Key": "k"}
    assert _auth_with_config_headers(None, None) is None


def test_explicit_auth_wins_over_config_headers():
    explicit = Auth.bearer("cli-token")
    merged = _auth_with_config_headers(
        explicit, {"authorization": "Bearer config", "X-Trace": "1"}
    )
    assert merged.custom_headers == {"X-Trace": "1"}
    assert merged.type == AuthType.BEARER
    assert merged.bearer_token == "cli-token"
    assert explicit.custom_headers == {}

    apikey = Auth.apikey("cli-key", "X-Api-Key")
    merged = _auth_with_config_headers(apikey, {"x-api-key": "config", "X-A": "a"})
    assert merged.custom_headers == {"X-A": "a"}

    custom = Auth(custom_headers={"X-A": "cli"})
    merged = _auth_with_config_headers(custom, {"x-a": "config", "X-B": "b"})
    assert merged.custom_headers == {"X-B": "b", "X-A": "cli"}


@pytest.mark.asyncio
async def test_stdio_session_starts_the_server_in_its_cwd(tmp_path):
    captured = {}

    def fake_stdio_client(params, errlog=None):
        captured["params"] = params
        raise ConnectionError("stop after building the parameters")

    server = StdioServer(command="echo", args=["hi"], cwd=str(tmp_path))
    scanner = Scanner(Config())
    with patch("mcpscanner.core.scanner.stdio_client", fake_stdio_client):
        with pytest.raises(Exception):
            await scanner._get_stdio_session(server)
    assert str(captured["params"].cwd) == str(tmp_path)


@pytest.mark.parametrize(
    "platform, base",
    [
        ("linux", "~/.config"),
        ("darwin", "~/Library/Application Support"),
        ("win32", "~/AppData/Roaming"),
    ],
)
@pytest.mark.parametrize("profile", ["Code - Insiders", "VSCodium"])
@pytest.mark.parametrize("name", ["mcp.json", "settings.json"])
def test_well_known_paths_include_insiders_and_vscodium(platform, base, profile, name):
    with patch("mcpscanner.config.constants.sys.platform", platform):
        paths = MCPConfigScanner().constants.get_well_known_mcp_paths()
    assert f"{base}/{profile}/User/{name}" in paths
