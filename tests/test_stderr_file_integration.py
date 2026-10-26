# Copyright 2025 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Offline integration test: config scans redirect stdio server stderr."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "stdio_stderr_marker_server.py"
MARKER = "MCP_SCANNER_STDERR_MARKER"

pytestmark = pytest.mark.skipif(
    not hasattr(
        __import__("mcp.client.session", fromlist=["ClientSession"]).ClientSession,
        "discover",
    ),
    reason="mcp>=2.0 required for server/discover over stdio",
)


def _fixture_can_start() -> bool:
    """True when this platform can spawn the fixture and emit the marker."""
    try:
        proc = subprocess.Popen(
            [sys.executable, str(FIXTURE)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError:
        return False
    try:
        # communicate() closes stdin itself. Closing it first makes 3.11
        # flush the closed pipe and raise ValueError, which is not an OSError.
        try:
            _, err = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            _, err = proc.communicate()
    except OSError:
        proc.kill()
        return False
    return MARKER.encode() in err


@pytest.mark.asyncio
async def test_config_scan_redirects_server_stderr_to_file(
    tmp_path, capfd, monkeypatch
):
    """A real stdio server's startup marker goes to --stderr-file, not the terminal."""
    pytest.importorskip("mcp.server.mcpserver")
    if not _fixture_can_start():
        pytest.skip("stdio marker server cannot run on this platform")

    monkeypatch.setenv("MCP_SCANNER_STDIO_TIMEOUT", "8")
    monkeypatch.delenv("MCP_SCANNER_API_KEY", raising=False)
    monkeypatch.delenv("MCP_SCANNER_LLM_API_KEY", raising=False)

    config_path = tmp_path / "mcp.json"
    log_path = tmp_path / "server-stderr.log"
    config_path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "marker": {
                        "command": sys.executable,
                        "args": [str(FIXTURE)],
                    }
                }
            }
        )
    )

    from mcpscanner.cli import main

    argv = [
        "mcp-scanner",
        "--analyzers",
        "yara",
        "config",
        "--config-path",
        str(config_path),
        "--stderr-file",
        str(log_path),
    ]
    with patch("sys.argv", argv):
        await main()

    captured = capfd.readouterr()
    log_text = log_path.read_text()

    assert MARKER in log_text
    assert MARKER not in captured.err
    assert MARKER not in captured.out
    # The file is the server process stderr, not the scanner's own log stream.
    assert "mcpscanner" not in log_text
    assert "MCP Scanner Results Summary" in captured.out
