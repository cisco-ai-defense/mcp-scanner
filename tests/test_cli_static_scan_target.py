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

"""`static` reports must name the scanned files, not the --server-url default."""

import argparse
import json
from unittest.mock import patch

import pytest

from mcpscanner.cli import main

DEFAULT_SERVER_URL = "https://mcp.deepwiki.com/mcp"

TOOLS = {
    "tools": [
        {
            "name": "add",
            "description": "Adds two numbers.",
            "inputSchema": {"type": "object", "properties": {"a": {"type": "number"}}},
        }
    ]
}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "report_args",
    [
        ["--format", "summary"],
        ["--format", "table"],
        ["--format", "detailed"],
        ["--detailed"],
    ],
)
async def test_static_report_names_tools_file(tmp_path, capsys, report_args):
    tools_file = tmp_path / "tools.json"
    tools_file.write_text(json.dumps(TOOLS), encoding="utf-8")

    argv = [
        "mcp-scanner",
        "--analyzers",
        "yara",
        *report_args,
        "static",
        "--tools",
        str(tools_file),
    ]
    with patch("sys.argv", argv):
        await main()

    out = capsys.readouterr().out
    assert DEFAULT_SERVER_URL not in out
    if report_args == ["--format", "table"]:
        # The table truncates the Scan Target column to a fixed width.
        assert "static:" in out
    else:
        assert f"static:{tools_file}" in out


def test_static_scan_label_lists_every_scanned_file():
    from mcpscanner.cli import _static_scan_label

    args = argparse.Namespace(
        tools="tools.json", prompts=None, resources="resources.json"
    )

    assert _static_scan_label(args) == "static:tools.json,resources.json"
