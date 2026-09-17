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

"""Tests that a scan never leaves an MCP session open.

Every scan_* method used to carry its own ``finally: await
_close_mcp_session(...)``. The teardown now lives in two context managers, so
these tests cover the context managers directly and assert structurally that
no scan method has gone back to opening a session by hand.
"""

import ast
import inspect
from unittest.mock import AsyncMock

import pytest

from mcpscanner import Config, Scanner
from mcpscanner.core import scanner as scanner_module
from mcpscanner.core.mcp_models import StdioServer


@pytest.fixture
def scanner():
    return Scanner(Config(api_key="k"))


class TestRemoteSessionContextManager:
    @pytest.mark.asyncio
    async def test_closes_after_a_clean_body(self, scanner, monkeypatch):
        ctx, session = object(), object()
        close = AsyncMock()
        monkeypatch.setattr(
            scanner, "_get_mcp_session", AsyncMock(return_value=(ctx, session))
        )
        monkeypatch.setattr(scanner, "_close_mcp_session", close)

        async with scanner._remote_session("http://x") as yielded:
            assert yielded is session

        close.assert_awaited_once_with(ctx, session)

    @pytest.mark.asyncio
    async def test_closes_when_the_body_raises(self, scanner, monkeypatch):
        ctx, session = object(), object()
        close = AsyncMock()
        monkeypatch.setattr(
            scanner, "_get_mcp_session", AsyncMock(return_value=(ctx, session))
        )
        monkeypatch.setattr(scanner, "_close_mcp_session", close)

        with pytest.raises(RuntimeError):
            async with scanner._remote_session("http://x"):
                raise RuntimeError("scan blew up")

        close.assert_awaited_once_with(ctx, session)

    @pytest.mark.asyncio
    async def test_closes_when_the_connection_itself_fails(self, scanner, monkeypatch):
        # Nothing was opened, but the close still runs and must tolerate None.
        close = AsyncMock()
        monkeypatch.setattr(
            scanner, "_get_mcp_session", AsyncMock(side_effect=OSError("refused"))
        )
        monkeypatch.setattr(scanner, "_close_mcp_session", close)

        with pytest.raises(OSError):
            async with scanner._remote_session("http://x"):
                pytest.fail("body must not run when the connection fails")

        close.assert_awaited_once_with(None, None)


class TestStdioSessionContextManager:
    @pytest.mark.asyncio
    async def test_closes_when_the_body_raises(self, scanner, monkeypatch):
        ctx, session = object(), object()
        close = AsyncMock()
        monkeypatch.setattr(
            scanner, "_get_stdio_session", AsyncMock(return_value=(ctx, session))
        )
        monkeypatch.setattr(scanner, "_close_mcp_session", close)

        config = StdioServer(command="echo", args=[])
        with pytest.raises(RuntimeError):
            async with scanner._stdio_session(config, 5, None):
                raise RuntimeError("scan blew up")

        close.assert_awaited_once_with(ctx, session)


class TestNoHandRolledTeardown:
    """The whole point of the context managers is that nobody re-opens by hand."""

    @staticmethod
    def scan_methods():
        source = inspect.getsource(scanner_module)
        cls = next(
            n
            for n in ast.parse(source).body
            if isinstance(n, ast.ClassDef) and n.name == "Scanner"
        )
        return [
            m
            for m in cls.body
            if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))
            and m.name.startswith("scan_")
        ]

    def test_scan_methods_do_not_open_sessions_directly(self):
        offenders = []
        for method in self.scan_methods():
            calls = {
                node.func.attr
                for node in ast.walk(method)
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            }
            if calls & {"_get_mcp_session", "_get_stdio_session"}:
                offenders.append(method.name)
        assert offenders == [], (
            f"{offenders} open a session directly; use _remote_session or "
            "_stdio_session so the teardown stays in one place"
        )

    def test_scan_methods_do_not_close_sessions_directly(self):
        offenders = [
            m.name for m in self.scan_methods() if "_close_mcp_session" in ast.dump(m)
        ]
        assert offenders == []


class TestSessionClosedOnScanFailure:
    @pytest.mark.asyncio
    async def test_failed_tool_listing_still_closes(self, scanner, monkeypatch):
        ctx = object()
        session = AsyncMock()
        session.list_tools = AsyncMock(side_effect=RuntimeError("server died"))
        close = AsyncMock()
        monkeypatch.setattr(
            scanner, "_get_mcp_session", AsyncMock(return_value=(ctx, session))
        )
        monkeypatch.setattr(scanner, "_close_mcp_session", close)

        with pytest.raises(RuntimeError):
            await scanner.scan_remote_server_tools("http://x")

        close.assert_awaited_once_with(ctx, session)
