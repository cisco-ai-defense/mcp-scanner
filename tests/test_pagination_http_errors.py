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

"""Keep discovery error categories intact through the real REST endpoints."""

from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from mcpscanner.api.router import get_scanner, router
from mcpscanner.config.constants import MCPScannerConstants
from mcpscanner.core.exceptions import (
    MCPAuthenticationError,
    MCPConnectionError,
    MCPServerNotFoundError,
)
from tests.test_pagination import collect, page
from tests.test_scanner_pagination import (
    PagedSession,
    bind_session,
    listed_item,
    listing,
    scanner,
)


async def request_scan(scanner, collection, single):
    """Call the ASGI router with real scanner code and only transport replaced."""
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_scanner] = lambda: lambda analyzers: scanner
    payload = {
        "server_url": "https://pagination.example/mcp",
        "analyzers": ["yara"],
        "enable_meta": False,
    }
    if single:
        key = "resource_uri" if collection == "resources" else f"{collection[:-1]}_name"
        payload[key] = "resource://target" if collection == "resources" else "target"
    endpoint = f"/scan-{collection[:-1]}" if single else f"/scan-all-{collection}"
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        return await client.post(endpoint, json=payload)


@pytest.mark.asyncio
@pytest.mark.parametrize("first_page", [True, False])
@pytest.mark.parametrize(
    "error_type", [MCPAuthenticationError, MCPServerNotFoundError, MCPConnectionError]
)
async def test_typed_connection_errors_keep_their_identity(first_page, error_type):
    """Already classified failures must not be recategorized by pagination."""
    error = error_type("classified failure")
    list_page = AsyncMock(
        side_effect=[error] if first_page else [page(cursor="next"), error]
    )
    with pytest.raises(error_type) as caught:
        await collect(list_page)
    assert caught.value is error
    assert list_page.await_count == (1 if first_page else 2)


@pytest.mark.asyncio
@pytest.mark.parametrize("collection", ["tools", "prompts", "resources"])
@pytest.mark.parametrize("single", [False, True], ids=["bulk", "single"])
@pytest.mark.parametrize("first_page", [True, False])
async def test_api_discovery_authentication_failure_is_401(
    scanner, bind_session, collection, single, first_page
):
    """Authentication errors remain 401 even after a named target was found."""
    error = MCPAuthenticationError("Authentication required")
    pages = (
        [error]
        if first_page
        else [listing(collection, [listed_item(collection, "target")], "next"), error]
    )
    session = PagedSession(collection, pages)
    context = bind_session(session)
    response = await request_scan(scanner, collection, single)
    assert response.status_code == 401, response.text
    assert response.json()["detail"] == str(error)
    assert len(session.list_requests) == (1 if first_page else 2)
    assert not session.body_requests
    session.call_tool.assert_not_awaited()
    assert session.closed and context.closed


@pytest.mark.asyncio
@pytest.mark.parametrize("collection", ["tools", "prompts", "resources"])
@pytest.mark.parametrize("single", [False, True], ids=["bulk", "single"])
@pytest.mark.parametrize(
    "setting",
    ["MAX_MCP_LIST_PAGES", "MAX_MCP_LIST_ITEMS", "MCP_LIST_PAGE_TIMEOUT_SECONDS"],
)
async def test_api_invalid_discovery_configuration_is_500(
    scanner, bind_session, monkeypatch, collection, single, setting
):
    """Local invalid limits are server failures, never missing remote items."""
    monkeypatch.setattr(MCPScannerConstants, setting, 0)
    session = PagedSession(collection, [listing(collection, [])])
    context = bind_session(session)
    response = await request_scan(scanner, collection, single)
    assert response.status_code == 500, response.text
    assert "positive" in response.json()["detail"]
    assert not session.list_requests
    assert not session.body_requests
    session.call_tool.assert_not_awaited()
    assert session.closed and context.closed


@pytest.mark.asyncio
@pytest.mark.parametrize("collection", ["tools", "prompts", "resources"])
async def test_api_missing_named_item_remains_404(scanner, bind_session, collection):
    """Preserve the existing not-found contract while fixing configuration errors."""
    session = PagedSession(collection, [listing(collection, [])])
    context = bind_session(session)
    response = await request_scan(scanner, collection, True)
    assert response.status_code == 404, response.text
    assert "not found" in response.json()["detail"].lower()
    assert session.closed and context.closed
