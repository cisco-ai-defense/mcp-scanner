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
import math
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import aclosing
from typing import Any

try:
    from mcp.shared.exceptions import MCPError as McpError
except ImportError:  # pragma: no cover - matches the scanner's SDK compatibility
    from mcp.shared.exceptions import McpError
from mcp.types import PaginatedRequestParams

from ..config.constants import MCPScannerConstants
from .exceptions import MCPConnectionError


class MCPPaginationError(MCPConnectionError):
    """An MCP server's inventory could not be discovered completely or uniquely."""


async def iter_mcp_items(
    list_page: Callable[..., Awaitable[Any]],
    items_attribute: str,
    *,
    max_pages: int | None = None,
    max_items: int | None = None,
    page_timeout: float | None = None,
) -> AsyncIterator[Any]:
    """Yield listed items in server order, following opaque pagination cursors.

    Defaults come from the scanner's configurable inventory limits. The timeout
    applies to every page, including the first, not to the complete operation.
    First-page MCP errors retain their type for existing capability handling;
    subsequent errors must not be mistaken for an absent capability. Cancellation
    propagates unchanged. Cursor values are never included in error messages.
    A caller that stops early must explicitly close this iterator.
    """
    if max_pages is None:
        max_pages = MCPScannerConstants.MAX_MCP_LIST_PAGES
    if max_items is None:
        max_items = MCPScannerConstants.MAX_MCP_LIST_ITEMS
    if page_timeout is None:
        page_timeout = MCPScannerConstants.MCP_LIST_PAGE_TIMEOUT_SECONDS
    if any(type(limit) is not int or limit < 1 for limit in (max_pages, max_items)):
        raise ValueError("MCP discovery page and item limits must be positive integers")
    if (
        type(page_timeout) not in (int, float)
        or not math.isfinite(page_timeout)
        or page_timeout <= 0
    ):
        raise ValueError("MCP list-page timeout must be a finite, positive number")

    cursor: str | None = None
    seen_cursors: set[str] = set()
    page_count = 0
    item_count = 0
    missing = object()

    while True:
        if page_count >= max_pages:
            raise MCPPaginationError(
                f"MCP {items_attribute} discovery exceeded the {max_pages}-page limit"
            )

        try:
            request = (
                list_page()
                if page_count == 0
                else list_page(params=PaginatedRequestParams(cursor=cursor))
            )
            page = await asyncio.wait_for(request, timeout=page_timeout)
        except asyncio.TimeoutError as error:
            raise MCPPaginationError(
                f"MCP {items_attribute} discovery timed out after {page_timeout:g} seconds "
                f"waiting for page {page_count + 1}"
            ) from error
        except McpError as error:
            if page_count == 0:
                raise
            raise MCPPaginationError(
                f"MCP {items_attribute} discovery failed on page {page_count + 1}"
            ) from error
        except Exception as error:
            # Only wrap errors raised while requesting a page, not local item
            # processing. CancelledError and GeneratorExit are BaseExceptions.
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

        # SDK 2 uses snake_case attributes; the protocol uses camelCase on wire.
        # A present None means end-of-list, not a reason to try another alias.
        cursor = getattr(page, "next_cursor", missing)
        if cursor is missing:
            cursor = getattr(page, "nextCursor", missing)
        if cursor is missing:
            raise MCPPaginationError(
                f"MCP {items_attribute} discovery response has no pagination cursor field"
            )
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


async def find_mcp_item(
    list_page: Callable[..., Awaitable[Any]],
    items_attribute: str,
    identifier_attribute: str,
    identifier: str,
) -> Any | None:
    """Find a unique item without silently accepting a later duplicate identity.

    A named scan must finish bounded discovery before analyzing its target.
    Duplicate tool/prompt names or resource URIs are ambiguous, so they fail
    rather than returning a potentially misleading first match. Explicitly
    close the iterator on duplicates, cancellation, and other early exits.
    """
    target = None
    async with aclosing(iter_mcp_items(list_page, items_attribute)) as items:
        async for item in items:
            if str(getattr(item, identifier_attribute)) == identifier:
                if target is not None:
                    raise MCPPaginationError(
                        f"MCP {items_attribute} discovery returned a duplicate "
                        f"{identifier_attribute} for the requested item"
                    )
                target = item
    return target
