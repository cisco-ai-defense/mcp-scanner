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

"""Bounded discovery for MCP's cursor-based list operations."""

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any

from mcp.shared.exceptions import McpError
from mcp.types import PaginatedRequestParams

from ..config.constants import MCPScannerConstants
from .exceptions import MCPScannerError

MAX_MCP_LIST_PAGES = 1000
MAX_MCP_LIST_ITEMS = 10000


class MCPPaginationError(MCPScannerError):
    """MCP discovery could not finish within its page, item, or time limits."""


async def iter_mcp_items(
    list_page: Callable[..., Awaitable[Any]],
    items_attribute: str,
    *,
    max_pages: int = MAX_MCP_LIST_PAGES,
    max_items: int = MAX_MCP_LIST_ITEMS,
) -> AsyncIterator[Any]:
    """Yield listed items in server order, following opaque pagination cursors.

    A caller looking for one item may stop iteration as soon as it is found.
    A bulk caller must exhaust discovery before reporting a complete scan.
    First-page MCP errors retain their type for existing capability handling;
    errors on subsequent pages must not be mistaken for an absent capability.
    Cursor values are never included in discovery error messages.
    """
    if any(type(limit) is not int or limit < 1 for limit in (max_pages, max_items)):
        raise ValueError("MCP discovery page and item limits must be positive integers")

    cursor: str | None = None
    seen_cursors: set[str] = set()
    page_count = 0
    item_count = 0

    while True:
        if page_count >= max_pages:
            raise MCPPaginationError(
                f"MCP {items_attribute} discovery exceeded the {max_pages}-page limit"
            )

        timeout = MCPScannerConstants.MCP_CONTENT_READ_TIMEOUT_SECONDS
        try:
            request = (
                list_page()
                if page_count == 0
                else list_page(params=PaginatedRequestParams(cursor=cursor))
            )
            page = await asyncio.wait_for(request, timeout=timeout)
        except asyncio.TimeoutError as error:
            raise MCPPaginationError(
                f"MCP {items_attribute} discovery timed out after {timeout:g} seconds "
                f"waiting for page {page_count + 1}"
            ) from error
        except McpError as error:
            if page_count == 0:
                raise
            raise MCPPaginationError(
                f"MCP {items_attribute} discovery failed on page {page_count + 1}"
            ) from error

        page_count += 1
        for item in getattr(page, items_attribute):
            if item_count >= max_items:
                raise MCPPaginationError(
                    f"MCP {items_attribute} discovery exceeded the {max_items}-item limit"
                )
            item_count += 1
            yield item

        cursor = getattr(page, "nextCursor", None)
        if cursor is None:
            return
        if not isinstance(cursor, str):
            raise MCPPaginationError(
                f"MCP {items_attribute} discovery returned an invalid cursor type"
            )
        if cursor in seen_cursors:
            raise MCPPaginationError(
                f"MCP {items_attribute} discovery returned a repeated cursor"
            )
        seen_cursors.add(cursor)
