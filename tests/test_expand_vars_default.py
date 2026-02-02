# Copyright 2026 Cisco Systems, Inc. and its affiliates
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

import json
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from mcpscanner import Config
from mcpscanner.core.models import AnalyzerEnum
from mcpscanner.core.scanner import Scanner


@pytest.mark.asyncio
async def test_scan_mcp_config_file_applies_expand_vars_default():
    data = {
        "mcpServers": {
            "local": {
                "command": "echo",
                "args": ["$HOME"],
            }
        }
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(data, f)
        path = f.name

    try:
        scanner = Scanner(Config())
        with patch.object(
            Scanner, "scan_stdio_server_tools", new=AsyncMock(return_value=[])
        ) as mock_scan:
            results = await scanner.scan_mcp_config_file(
                path, analyzers=[AnalyzerEnum.YARA], expand_vars_default="linux"
            )
            assert results == []
            assert mock_scan.call_count == 1
            stdio_cfg = mock_scan.call_args.args[0]
            assert getattr(stdio_cfg, "expand_vars") == "linux"
            assert stdio_cfg.command == "echo"
            assert stdio_cfg.args == ["$HOME"]
    finally:
        Path(path).unlink(missing_ok=True)
