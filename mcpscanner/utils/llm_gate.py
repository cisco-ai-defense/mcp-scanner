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
The limit is read once per event loop, under a lock, from
``MCP_SCANNER_LLM_REQUEST_CONCURRENCY``. A later change applies when a new
loop creates its own semaphore. Calls that already hold the old semaphore
keep it until they finish.
"""

from __future__ import annotations

import asyncio
import threading

from mcpscanner.config.constants import MCPScannerConstants

_gate: asyncio.Semaphore | None = None
_loop: asyncio.AbstractEventLoop | None = None
_lock = threading.Lock()


def llm_request_gate() -> asyncio.Semaphore:
    """Return the semaphore for the running event loop."""
    global _gate, _loop
    loop = asyncio.get_running_loop()
    with _lock:
        if _gate is None or _loop is not loop:
            try:
                limit = int(MCPScannerConstants.LLM_REQUEST_CONCURRENCY)
            except (TypeError, ValueError):
                limit = 8
            _gate = asyncio.Semaphore(max(1, limit))
            _loop = loop
        return _gate
