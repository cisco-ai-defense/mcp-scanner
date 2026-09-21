# Copyright 2025 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Integration tests for modern (2026-07-28) stdio MCP negotiation."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from mcpscanner import Config, Scanner
from mcpscanner.core.mcp_models import StdioServer
from mcpscanner.core.models import AnalyzerEnum

from tests.test_scanner import _mcp_error

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "stdio_echo_server.py"


@pytest.fixture
def config():
    return Config(api_key="test_api_key")


pytestmark = pytest.mark.skipif(
    not hasattr(__import__("mcp.client.session", fromlist=["ClientSession"]).ClientSession, "discover"),
    reason="mcp>=2.0 required for server/discover over stdio",
)


@pytest.mark.asyncio
async def test_stdio_modern_negotiates_2026(config):
    """MCPServer stdio should connect via discover() at 2026-07-28."""
    scanner = Scanner(config)
    server = StdioServer(command=sys.executable, args=[str(FIXTURE)])

    ctx, session = await scanner._get_stdio_session(server, timeout=30)
    try:
        assert session.protocol_version == "2026-07-28"
        assert session.discover_result is not None
        assert session.initialize_result is None

        tools = await session.list_tools()
        assert [tool.name for tool in tools.tools] == ["echo_tool"]
    finally:
        await scanner._close_mcp_session(ctx, session)


@pytest.mark.asyncio
async def test_stdio_scan_tools_modern_protocol(config):
    scanner = Scanner(config)
    server = StdioServer(command=sys.executable, args=[str(FIXTURE)])

    results = await scanner.scan_stdio_server_tools(
        server, analyzers=[AnalyzerEnum.YARA], timeout=30
    )

    assert len(results) == 1
    assert results[0].tool_name == "echo_tool"


@pytest.mark.asyncio
async def test_stdio_legacy_initialize_fallback(config):
    """Legacy stdio servers without server/discover still connect via initialize()."""
    scanner = Scanner(config)
    server = StdioServer(command=sys.executable, args=[str(FIXTURE)])

    with patch(
        "mcpscanner.core.scanner.ClientSession.discover",
        new_callable=AsyncMock,
        side_effect=_mcp_error(-32601, "Method not found"),
    ):
        ctx, session = await scanner._get_stdio_session(server, timeout=30)
        try:
            assert session.initialize_result is not None
            assert session.protocol_version is not None
            assert session.protocol_version != "2026-07-28"

            tools = await session.list_tools()
            assert [tool.name for tool in tools.tools] == ["echo_tool"]
        finally:
            await scanner._close_mcp_session(ctx, session)
