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

"""Process-wide cache for parsed Python ASTs.

Several layers of the behavioural pipeline historically re-parsed the same
Python source file:

* ``CallGraphAnalyzer.add_file`` (via ``PythonParser.parse``)
* ``ContextExtractor.__init__``
* ``NativeAnalyzer._analyze_python``

Each ``ast.parse`` call walks the source and allocates a fresh AST. On a
medium repo (~50 files, ~300 functions) that is several hundred milliseconds
of CPU spent producing identical trees. This module dedupes them.

Design notes:

- The cache key combines the file path and a content digest so that re-using
  the same path with mutated content (e.g. inline source overrides during
  tests) still produces the correct AST.
- AST objects are mutable; consumers that perform destructive transforms
  must copy first. None of the current call sites mutate the tree.
- A small bounded LRU keeps memory predictable on huge mono-repos. The
  default size easily covers typical MCP servers; on large-scale scans the
  oldest entries are evicted FIFO.
- Access is guarded by a module-level lock because
  ``BehavioralCodeAnalyzer`` parses files through ``asyncio.to_thread``.
"""

from __future__ import annotations

import ast
import hashlib
import logging
import threading
from collections import OrderedDict
from pathlib import Path
from typing import Optional, Union

logger = logging.getLogger(__name__)

# Bounded so a single very large scan can't hold every parsed AST in memory.
# Tunable via ``MCP_SCANNER_AST_CACHE_SIZE`` for users running on giant repos.
import os as _os

_AST_CACHE_MAX_ENTRIES = max(
    16, int(_os.environ.get("MCP_SCANNER_AST_CACHE_SIZE", "512") or "512")
)

_ast_cache: "OrderedDict[tuple, ast.AST]" = OrderedDict()
_lock = threading.Lock()
_stats = {"hits": 0, "misses": 0, "evictions": 0, "errors": 0}


def _digest(source_code: str) -> str:
    """Cheap, collision-resistant digest of the source content.

    SHA-256 truncated to 16 bytes — effectively zero collision risk for the
    handful of files in any single scan, but small enough to avoid carrying
    full hex strings in cache keys.
    """
    return hashlib.sha256(source_code.encode("utf-8", errors="replace")).hexdigest()[:32]


def get_python_ast(
    source_code: str,
    file_path: Optional[Union[str, Path]] = None,
) -> ast.AST:
    """Return a (cached) parsed AST for ``source_code``.

    Args:
        source_code: The Python source string.
        file_path: Optional path used both as part of the cache key and as
            the ``filename`` argument to ``ast.parse`` so syntax errors carry
            useful location information.

    Returns:
        Parsed AST module. May raise ``SyntaxError``; failures are logged
        and counted but not cached so retries against fixed content can
        succeed.
    """
    path_key = str(file_path) if file_path is not None else None
    key = (path_key, _digest(source_code))

    with _lock:
        cached = _ast_cache.get(key)
        if cached is not None:
            # LRU bookkeeping: move-to-end on hit so cold entries get evicted first
            _ast_cache.move_to_end(key)
            _stats["hits"] += 1
            return cached

    # Parse outside the lock so concurrent first-time parses of *different*
    # files don't serialize on each other. The duplicate-parse window for the
    # same file is tiny (microseconds) and the caller still gets a valid AST.
    try:
        tree = ast.parse(source_code, filename=path_key or "<string>")
    except SyntaxError:
        with _lock:
            _stats["errors"] += 1
        raise

    with _lock:
        # Another thread may have populated the cache while we parsed; reuse
        # whichever copy is already present so callers don't end up with two
        # separate AST objects for the same content (avoids subtle identity
        # mismatches in downstream analyzers).
        existing = _ast_cache.get(key)
        if existing is not None:
            _stats["hits"] += 1
            _ast_cache.move_to_end(key)
            return existing
        _ast_cache[key] = tree
        _stats["misses"] += 1
        # Evict oldest entries past the size budget.
        while len(_ast_cache) > _AST_CACHE_MAX_ENTRIES:
            _ast_cache.popitem(last=False)
            _stats["evictions"] += 1
        return tree


def ast_cache_stats() -> dict:
    """Return a snapshot of the AST cache counters (read-only)."""
    with _lock:
        return {
            "entries": len(_ast_cache),
            "max_entries": _AST_CACHE_MAX_ENTRIES,
            **_stats,
        }


def clear_ast_cache() -> None:
    """Drop every cached AST and reset counters. Intended for tests."""
    with _lock:
        _ast_cache.clear()
        for k in _stats:
            _stats[k] = 0
