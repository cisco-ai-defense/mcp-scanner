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

"""Deterministic limits and protocol checks for MCP inventory pagination."""

import asyncio
from unittest.mock import AsyncMock, call

import pytest
from mcp.shared.exceptions import McpError
from mcp.types import ErrorData, ListToolsResult, PaginatedRequestParams, Tool

from mcpscanner.config.constants import MCPScannerConstants
from mcpscanner.core.pagination import MCPPaginationError, iter_mcp_items


def tool(name):
    return Tool(name=name, inputSchema={"type": "object"})


def page(*names, cursor=None):
    return ListToolsResult(tools=[tool(name) for name in names], nextCursor=cursor)


async def collect(list_page, **limits):
    return [item async for item in iter_mcp_items(list_page, "tools", **limits)]


@pytest.mark.asyncio
async def test_request_params_preserve_opaque_cursors_and_empty_pages():
    list_page = AsyncMock(
        side_effect=[
            page("first", cursor=""),
            page(cursor="opaque: /?page=three=="),
            page("last"),
        ]
    )

    result = await collect(list_page)

    assert [item.name for item in result] == ["first", "last"]
    assert list_page.await_args_list == [
        call(),
        call(params=PaginatedRequestParams(cursor="")),
        call(params=PaginatedRequestParams(cursor="opaque: /?page=three==")),
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "cursors", [("private-cursor", "private-cursor"), ("", ""), ("a", "b", "a")]
)
async def test_cursor_cycles_fail_before_an_extra_request(cursors):
    list_page = AsyncMock(side_effect=[page(cursor=cursor) for cursor in cursors])

    with pytest.raises(MCPPaginationError, match="repeated cursor") as caught:
        await collect(list_page)

    assert list_page.await_count == len(cursors)
    assert "private-cursor" not in str(caught.value)


@pytest.mark.asyncio
async def test_distinct_cursors_cannot_exceed_page_budget():
    list_page = AsyncMock(
        side_effect=[
            page("first", cursor="private-one"),
            page("second", cursor="private-two"),
            page("never-requested"),
        ]
    )

    with pytest.raises(MCPPaginationError, match="2-page limit") as caught:
        await collect(list_page, max_pages=2)

    assert list_page.await_count == 2
    assert "private-" not in str(caught.value)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "pages,max_pages,max_items,expected",
    [
        ([page()], 1, 1, []),
        ([page("only")], 1, 1, ["only"]),
        ([page("first", cursor="next"), page("last")], 2, 2, ["first", "last"]),
        ([page("only", cursor="next"), page()], 2, 1, ["only"]),
    ],
)
async def test_exact_limits_allow_a_complete_final_page(
    pages, max_pages, max_items, expected
):
    list_page = AsyncMock(side_effect=pages)

    result = await collect(list_page, max_pages=max_pages, max_items=max_items)

    assert [item.name for item in result] == expected
    assert list_page.await_count == len(pages)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "pages,expected_requests",
    [
        ([page("first", "second", "excess")], 1),
        ([page("first", cursor="next"), page("second", "excess")], 2),
    ],
)
async def test_entry_budget_applies_within_and_across_pages(pages, expected_requests):
    list_page = AsyncMock(side_effect=pages)
    observed = []

    with pytest.raises(MCPPaginationError, match="2-item limit"):
        async for item in iter_mcp_items(list_page, "tools", max_items=2):
            observed.append(item.name)

    assert observed == ["first", "second"]
    assert list_page.await_count == expected_requests


@pytest.mark.asyncio
async def test_early_consumer_does_not_request_or_validate_unneeded_pages():
    list_page = AsyncMock(
        side_effect=[page("target", "unneeded", cursor="next"), AssertionError()]
    )
    stream = iter_mcp_items(list_page, "tools", max_pages=1, max_items=1)
    try:
        assert (await anext(stream)).name == "target"
    finally:
        await stream.aclose()

    list_page.assert_awaited_once_with()


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["max_pages", "max_items"])
@pytest.mark.parametrize("value", [0, -1, True, 1.5, float("nan"), float("inf"), "1"])
async def test_invalid_limits_fail_without_starting_discovery(field, value):
    list_page = AsyncMock(return_value=page())

    with pytest.raises(ValueError, match="positive integers"):
        await collect(list_page, **{field: value})

    list_page.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("first_page", [True, False])
async def test_only_initial_protocol_error_retains_missing_capability_semantics(
    first_page,
):
    error = McpError(ErrorData(code=-32601, message="Method not found"))
    list_page = AsyncMock(
        side_effect=[error] if first_page else [page(cursor="next"), error]
    )

    with pytest.raises(McpError if first_page else MCPPaginationError) as caught:
        await collect(list_page)

    assert (caught.value if first_page else caught.value.__cause__) is error
    assert list_page.await_count == (1 if first_page else 2)


@pytest.mark.asyncio
@pytest.mark.parametrize("blocked_page_number", [1, 2])
async def test_each_list_request_has_a_timeout(monkeypatch, blocked_page_number):
    monkeypatch.setattr(MCPScannerConstants, "MCP_CONTENT_READ_TIMEOUT_SECONDS", 0.01)
    calls = 0
    cancelled = asyncio.Event()

    async def list_page(**_kwargs):
        nonlocal calls
        calls += 1
        if calls < blocked_page_number:
            return page(cursor="next")
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()

    with pytest.raises(
        MCPPaginationError, match=f"timed out.*page {blocked_page_number}"
    ):
        await collect(list_page)

    assert calls == blocked_page_number
    assert cancelled.is_set()


@pytest.mark.asyncio
@pytest.mark.parametrize("cursor", [False, 12, [], {}])
async def test_invalid_cursor_is_not_silently_treated_as_end_of_list(cursor):
    # A defensive unit boundary: normal MCP decoding validates this field first.
    malformed = ListToolsResult.model_construct(tools=[], nextCursor=cursor)
    list_page = AsyncMock(return_value=malformed)

    with pytest.raises(MCPPaginationError, match="invalid cursor type"):
        await collect(list_page)

    list_page.assert_awaited_once_with()
