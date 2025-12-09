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


