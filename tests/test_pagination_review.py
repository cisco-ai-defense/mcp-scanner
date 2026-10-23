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

"""Regressions for pagination review: SDK 2, API errors and complete named scans."""

import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from mcpscanner import Config, Scanner
from mcpscanner.api.router import get_scanner, router
from mcpscanner.config.constants import MCPScannerConstants
from mcpscanner.core.exceptions import MCPConfigurationError
from mcpscanner.core.mcp_models import StdioServer
from mcpscanner.core.models import AnalyzerEnum
from mcpscanner.core.pagination import MCPPaginationError
from tests.test_pagination import collect, page, tool
from tests.test_scanner_pagination import (
    COLLECTIONS,
    PagedSession,
    bind_session,
    listed_item,
    listing,
    result_name,
    scan,
    scanner,
)


@pytest.mark.asyncio
@pytest.mark.parametrize("first_page", [True, False])
@pytest.mark.parametrize("error_type", [RuntimeError, OSError])
async def test_request_errors_are_wrapped_without_exposing_details(
    first_page, error_type
):
    """All page request failures retain their cause but hide transport details."""
    error = error_type("private-token-in-transport-message")
    list_page = AsyncMock(
        side_effect=[error] if first_page else [page(cursor="next"), error]
    )
    with pytest.raises(MCPPaginationError, match="failed on page") as caught:
        await collect(list_page)
    assert caught.value.__cause__ is error
    assert "private-token" not in str(caught.value)


@pytest.mark.asyncio
@pytest.mark.parametrize("cursor_field", ["next_cursor", "nextCursor"])
async def test_cursor_aliases_continue_discovery(cursor_field):
    """Both SDK attribute spellings must follow the second page."""
    list_page = AsyncMock(
        side_effect=[
            SimpleNamespace(tools=[tool("first")], **{cursor_field: "next"}),
            SimpleNamespace(tools=[tool("last")], **{cursor_field: None}),
        ]
    )
    assert [item.name for item in await collect(list_page)] == ["first", "last"]
    assert list_page.await_count == 2


@pytest.mark.asyncio
async def test_explicit_end_cursor_does_not_fall_back_to_legacy_alias():
    """A present SDK 2 end marker wins over a stale legacy attribute."""
    list_page = AsyncMock(
        return_value=SimpleNamespace(tools=[], next_cursor=None, nextCursor="unused")
    )
    assert await collect(list_page) == []
    list_page.assert_awaited_once_with()


@pytest.mark.asyncio
async def test_missing_cursor_field_is_not_accepted_as_complete():
    """A malformed response cannot silently masquerade as a final page."""
    with pytest.raises(MCPPaginationError, match="no pagination cursor field"):
        await collect(AsyncMock(return_value=SimpleNamespace(tools=[])))


@pytest.mark.asyncio
@pytest.mark.parametrize("value", [0, -1, True, "30", float("inf"), float("nan")])
async def test_invalid_list_timeout_fails_before_request(value):
    """Reject unbounded or nonsensical timeout settings without making a call."""
    list_page = AsyncMock(return_value=page())
    with pytest.raises(MCPConfigurationError, match="finite, positive"):
        await collect(list_page, page_timeout=value)
    list_page.assert_not_awaited()


@pytest.mark.asyncio
async def test_list_timeout_is_independent_of_content_read_timeout(monkeypatch):
    """A short body-read budget must not change a valid list-page request."""
    monkeypatch.setattr(MCPScannerConstants, "MCP_CONTENT_READ_TIMEOUT_SECONDS", 0.001)
    monkeypatch.setattr(MCPScannerConstants, "MCP_LIST_PAGE_TIMEOUT_SECONDS", 1)

    async def delayed_page():
        """Return within the list timeout but outside the content timeout."""
        await asyncio.sleep(0.01)
        return page("only")

    assert [item.name for item in await collect(delayed_page)] == ["only"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "attribute,pattern",
    [
        ("MAX_MCP_LIST_PAGES", "1-page limit"),
        ("MAX_MCP_LIST_ITEMS", "1-item limit"),
    ],
)
async def test_discovery_uses_configured_default_limits(
    monkeypatch, attribute, pattern
):
    """The public scanner's configured defaults reach the iterator at runtime."""
    monkeypatch.setattr(MCPScannerConstants, attribute, 1)
    list_page = AsyncMock(side_effect=[page("first", cursor="next"), page("last")])
    with pytest.raises(MCPPaginationError, match=pattern):
        await collect(list_page)


@pytest.mark.asyncio
async def test_named_lookup_closes_iterator_immediately_on_duplicate(monkeypatch):
    """An ambiguity error must close the suspended iterator before returning."""
    import mcpscanner.core.pagination as pagination

    closed = []

    async def duplicate_items(*_args):
        """Expose whether the consumer deterministically executes finalization."""
        try:
            yield tool("target")
            yield tool("target")
            pytest.fail("lookup should stop once ambiguity is established")
        finally:
            closed.append(True)

    monkeypatch.setattr(pagination, "iter_mcp_items", duplicate_items)
    with pytest.raises(MCPPaginationError, match="duplicate name"):
        await pagination.find_mcp_item(AsyncMock(), "tools", "name", "target")
    assert closed == [True]


def test_discovery_environment_configuration():
    """Environment overrides are loaded before import, as documented."""
    environment = dict(os.environ)
    environment.update(
        {
            "MCP_SCANNER_MCP_LIST_PAGE_TIMEOUT_SECONDS": "45.5",
            "MCP_SCANNER_MAX_MCP_LIST_PAGES": "1200",
            "MCP_SCANNER_MAX_MCP_LIST_ITEMS": "20000",
        }
    )
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import json; from mcpscanner.config.constants import MCPScannerConstants as C; "
                "print(json.dumps([C.MCP_LIST_PAGE_TIMEOUT_SECONDS, C.MAX_MCP_LIST_PAGES, "
                "C.MAX_MCP_LIST_ITEMS]))"
            ),
        ],
        env=environment,
        check=True,
        text=True,
        capture_output=True,
        timeout=30,
    )
    assert json.loads(result.stdout.strip().splitlines()[-1]) == [45.5, 1200, 20000]


@pytest.mark.asyncio
@pytest.mark.parametrize("collection,transport", COLLECTIONS)
@pytest.mark.parametrize("across_pages", [False, True])
async def test_named_scan_rejects_duplicate_identity(
    scanner, bind_session, monkeypatch, collection, transport, across_pages
):
    """A benign first match must not hide a different same-identity entry."""
    benign = listed_item(collection, "target", description="Weather forecast.")
    different = listed_item(collection, "target", description="A different definition.")
    pages = (
        [listing(collection, [benign], "next"), listing(collection, [different])]
        if across_pages
        else [listing(collection, [benign, different])]
    )
    session = PagedSession(collection, pages)
    context = bind_session(session)
    analyzer = AsyncMock()
    monkeypatch.setattr(scanner, f"_analyze_{collection[:-1]}", analyzer)
    with pytest.raises(MCPPaginationError, match="duplicate"):
        await scan(scanner, collection, transport, target="target")
    analyzer.assert_not_awaited()
    session.call_tool.assert_not_awaited()
    assert not session.body_requests
    assert session.closed and context.closed


@pytest.mark.asyncio
@pytest.mark.parametrize("collection,transport", COLLECTIONS)
async def test_named_scan_fails_when_later_page_fails_after_match(
    scanner, bind_session, collection, transport
):
    """A found target is not reported safe when uniqueness cannot be checked."""
    session = PagedSession(
        collection,
        [
            listing(collection, [listed_item(collection, "target")], "next"),
            RuntimeError("transport closed"),
        ],
    )
    context = bind_session(session)
    with pytest.raises(MCPPaginationError, match="page 2"):
        await scan(scanner, collection, transport, target="target")
    assert not session.body_requests
    assert session.closed and context.closed


@pytest.mark.asyncio
@pytest.mark.parametrize("collection", ["tools", "prompts", "resources"])
@pytest.mark.parametrize("single", [False, True], ids=["bulk", "single"])
async def test_real_api_maps_pagination_failure_to_502(
    scanner, bind_session, collection, single
):
    """A repeated remote cursor reaches the real router as HTTP 502, not 500."""
    session = PagedSession(
        collection,
        [
            listing(collection, [], "repeated"),
            listing(collection, [], "repeated"),
        ],
    )
    context = bind_session(session)
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
        response = await client.post(endpoint, json=payload)
    assert response.status_code == 502, response.text
    assert "repeated cursor" in response.json()["detail"]
    assert session.closed and context.closed


@pytest.mark.asyncio
@pytest.mark.parametrize("collection", ["tools", "prompts"])
@pytest.mark.parametrize("single", [False, True], ids=["bulk", "single"])
@pytest.mark.parametrize("protocol", ["legacy", "modern"])
async def test_real_stdio_sdk2_follows_wire_pagination(collection, single, protocol):
    """Use the actual SDK client, subprocess transport, and local YARA analyzer."""
    scanner = Scanner(Config())
    fixture_name = (
        "stdio_modern_paginated_server.py"
        if protocol == "modern"
        else "stdio_paginated_server.py"
    )
    fixture = Path(__file__).parent / "fixtures" / fixture_name
    server = StdioServer(command=sys.executable, args=[str(fixture)])
    entity = collection[:-1] if single else collection
    method = getattr(scanner, f"scan_stdio_server_{entity}")
    arguments = [server, "later"] if single else [server]
    result = await asyncio.wait_for(
        method(*arguments, analyzers=[AnalyzerEnum.YARA], timeout=10), timeout=20
    )
    results = [result] if single else result
    assert [result_name(collection, item) for item in results] == (
        ["later"] if single else ["first", "later"]
    )
    assert results[-1].is_safe is False
    assert any(finding.analyzer == "YARA" for finding in results[-1].findings)


@pytest.mark.asyncio
@pytest.mark.parametrize("collection", ["tools", "prompts"])
@pytest.mark.parametrize("protocol", ["legacy", "modern"])
async def test_real_stdio_named_scan_rejects_later_duplicate(collection, protocol):
    """Verify duplicate rejection across empty pages with an actual SDK session."""
    scanner = Scanner(Config())
    fixture_name = (
        "stdio_modern_paginated_server.py"
        if protocol == "modern"
        else "stdio_paginated_server.py"
    )
    fixture = Path(__file__).parent / "fixtures" / fixture_name
    server = StdioServer(command=sys.executable, args=[str(fixture), "--duplicates"])
    method = getattr(scanner, f"scan_stdio_server_{collection[:-1]}")
    with pytest.raises(MCPPaginationError, match="duplicate name"):
        await asyncio.wait_for(
            method(server, "first", analyzers=[AnalyzerEnum.YARA], timeout=10),
            timeout=20,
        )
