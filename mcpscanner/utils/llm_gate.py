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

"""Process-wide limit on in-flight LLM HTTP calls.

Threat analysis, meta, readiness, and alignment all take this semaphore.
Each event loop keeps its own semaphore, created once from
``MCP_SCANNER_LLM_REQUEST_CONCURRENCY``. A later change of that limit does
not replace a loop's semaphore. Time spent waiting for the semaphore does
not consume the active item deadline.
"""

from __future__ import annotations

import asyncio
import threading
from contextlib import asynccontextmanager
from typing import AsyncIterator, Optional
from weakref import WeakKeyDictionary

from mcpscanner.config.constants import MCPScannerConstants

_semaphores: WeakKeyDictionary[asyncio.AbstractEventLoop, asyncio.Semaphore] = (
    WeakKeyDictionary()
)
_lock = threading.Lock()


def _limit() -> int:
    """The configured LLM concurrency, at least one."""
    try:
        limit = int(MCPScannerConstants.LLM_REQUEST_CONCURRENCY)
    except (TypeError, ValueError):
        limit = 8
    return max(1, limit)


def semaphore_for_running_loop() -> asyncio.Semaphore:
    """Return the stable semaphore for the running event loop."""
    loop = asyncio.get_running_loop()
    with _lock:
        sem = _semaphores.get(loop)
        if sem is None:
            sem = asyncio.Semaphore(_limit())
            _semaphores[loop] = sem
        return sem


def _active_item_budget() -> Optional[object]:
    """The item budget on this task, if a scan has started one."""
    from mcpscanner.core.scanner import _item_budget_var

    return _item_budget_var.get()


@asynccontextmanager
async def llm_request_gate() -> AsyncIterator[None]:
    """Hold one LLM slot. Queue time does not count against the item deadline."""
    sem = semaphore_for_running_loop()
    budget = _active_item_budget()
    pause = getattr(budget, "pause", None)
    resume = getattr(budget, "resume", None)
    if pause is not None:
        pause()
    try:
        await sem.acquire()
    finally:
        if resume is not None:
            resume()
    try:
        yield
    finally:
        sem.release()
