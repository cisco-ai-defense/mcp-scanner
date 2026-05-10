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

"""Shared in-process file content cache for the static-analysis pipeline.

Several stages (call-graph builder, ``ContextExtractor``, ``NativeAnalyzer``,
behavioural analyzer) read the same source files during a single scan. This
module deduplicates that I/O so each file is read at most once per process,
and lets the pipeline issue many reads concurrently when ``aiofiles`` is
available (otherwise it falls back to ``asyncio.to_thread``).

Patterned after ``cisco-ai-defense/aibom``'s ``scanners/file_cache.py``: the
cache is keyed by absolute path, sync and async helpers share the same
backing dict, and a ``threading.Lock`` keeps it safe across executor threads.
"""

from __future__ import annotations

import asyncio
import os
import threading
from pathlib import Path
from typing import Iterable, Union

PathLike = Union[Path, str]

_lock = threading.Lock()
_cache: dict[str, str] = {}
_hit_count = 0
_miss_count = 0


def _key(path: PathLike) -> str:
    return os.fspath(path)


def read_text_cached(
    path: PathLike,
    *,
    encoding: str = "utf-8",
    errors: str = "replace",
) -> str:
    """Read a file's text, returning a cached copy on subsequent calls.

    The first call performs the actual disk read; later calls for the same
    *path* (string-equal) return the cached string directly.
    """
    global _hit_count, _miss_count
    key = _key(path)
    with _lock:
        if key in _cache:
            _hit_count += 1
            return _cache[key]

    text = Path(key).read_text(encoding=encoding, errors=errors)
    with _lock:
        if key not in _cache:
            _cache[key] = text
            _miss_count += 1
        else:
            _hit_count += 1
    return _cache[key]


async def read_text_cached_async(
    path: PathLike,
    *,
    encoding: str = "utf-8",
    errors: str = "replace",
) -> str:
    """Async variant of :func:`read_text_cached`.

    Uses ``aiofiles`` for true non-blocking I/O when available; otherwise
    falls back to a thread executor via :func:`asyncio.to_thread` so the
    event loop is never blocked on disk reads. Either way the result is
    written to the same cache used by the sync helper.
    """
    global _hit_count, _miss_count
    key = _key(path)
    with _lock:
        if key in _cache:
            _hit_count += 1
            return _cache[key]

    try:
        import aiofiles  # type: ignore[import-not-found]

        async with aiofiles.open(key, encoding=encoding, errors=errors) as f:
            text = await f.read()
    except ImportError:
        text = await asyncio.to_thread(
            Path(key).read_text, encoding=encoding, errors=errors
        )

    with _lock:
        if key not in _cache:
            _cache[key] = text
            _miss_count += 1
        else:
            _hit_count += 1
    return _cache[key]


async def warm_cache_async(
    paths: Iterable[PathLike],
    *,
    encoding: str = "utf-8",
    errors: str = "replace",
    concurrency: int = 32,
) -> int:
    """Pre-populate the cache by reading *paths* concurrently.

    Returns the number of files successfully cached during this call. Files
    already in the cache are skipped, and OS errors on individual files are
    swallowed (they will surface naturally when a downstream caller asks for
    that file).

    Call this once early in the pipeline so subsequent
    :func:`read_text_cached` / :func:`read_text_cached_async` calls become
    in-memory hits. ``concurrency`` should be tuned to the underlying
    filesystem; 32 is a safe default for SSDs and remote filesystems.
    """
    uncached: list[str] = []
    with _lock:
        for p in paths:
            key = _key(p)
            if key not in _cache:
                uncached.append(key)

    if not uncached:
        return 0

    sem = asyncio.Semaphore(max(1, int(concurrency)))
    loaded = 0
    loaded_lock = threading.Lock()

    async def _read_one(key: str) -> None:
        nonlocal loaded
        async with sem:
            try:
                try:
                    import aiofiles  # type: ignore[import-not-found]

                    async with aiofiles.open(
                        key, encoding=encoding, errors=errors
                    ) as f:
                        text = await f.read()
                except ImportError:
                    text = await asyncio.to_thread(
                        Path(key).read_text, encoding=encoding, errors=errors
                    )
            except OSError:
                return

            with _lock:
                if key in _cache:
                    return
                _cache[key] = text
                global _miss_count
                _miss_count += 1

            with loaded_lock:
                loaded += 1

    await asyncio.gather(*(_read_one(k) for k in uncached))
    return loaded


def cache_stats() -> dict[str, int]:
    """Return hit / miss / size statistics for diagnostics."""
    with _lock:
        return {
            "hits": _hit_count,
            "misses": _miss_count,
            "entries": len(_cache),
        }


def clear_cache() -> None:
    """Reset the cache. Intended for tests and long-running processes."""
    global _hit_count, _miss_count
    with _lock:
        _cache.clear()
        _hit_count = 0
        _miss_count = 0
