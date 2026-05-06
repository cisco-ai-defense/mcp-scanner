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

"""Unit tests for the shared static-analysis file content cache."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from mcpscanner.core.static_analysis import file_cache


@pytest.fixture(autouse=True)
def _reset_cache():
    file_cache.clear_cache()
    yield
    file_cache.clear_cache()


def _write(tmp_path: Path, name: str, body: str) -> Path:
    p = tmp_path / name
    p.write_text(body, encoding="utf-8")
    return p


def test_sync_first_read_is_a_miss_then_hits(tmp_path: Path) -> None:
    f = _write(tmp_path, "a.py", "print('hello')\n")

    text1 = file_cache.read_text_cached(f)
    text2 = file_cache.read_text_cached(f)
    text3 = file_cache.read_text_cached(str(f))

    assert text1 == text2 == text3 == "print('hello')\n"
    stats = file_cache.cache_stats()
    assert stats["entries"] == 1
    assert stats["misses"] == 1
    assert stats["hits"] == 2


def test_sync_cache_returns_stale_content_after_disk_change(
    tmp_path: Path,
) -> None:
    f = _write(tmp_path, "b.py", "v1\n")

    first = file_cache.read_text_cached(f)
    f.write_text("v2\n", encoding="utf-8")
    second = file_cache.read_text_cached(f)

    assert first == "v1\n"
    assert second == "v1\n", (
        "the cache is per-process and intentionally does not invalidate on "
        "mtime; downstream code must call clear_cache() between scans if "
        "live edits are expected"
    )


def test_async_read_uses_same_cache_as_sync(tmp_path: Path) -> None:
    f = _write(tmp_path, "c.py", "data\n")

    sync_text = file_cache.read_text_cached(f)
    async_text = asyncio.run(file_cache.read_text_cached_async(f))

    assert sync_text == async_text == "data\n"
    stats = file_cache.cache_stats()
    assert stats["entries"] == 1
    assert stats["hits"] == 1
    assert stats["misses"] == 1


def test_warm_cache_async_prefetches_concurrently(tmp_path: Path) -> None:
    files = [
        _write(tmp_path, f"f{i}.py", f"# file {i}\n") for i in range(8)
    ]

    loaded = asyncio.run(
        file_cache.warm_cache_async(files, concurrency=4)
    )

    assert loaded == len(files)
    stats = file_cache.cache_stats()
    assert stats["entries"] == len(files)
    assert stats["misses"] == len(files)

    for f in files:
        assert file_cache.read_text_cached(f) == f"# file {f.stem[1:]}\n"

    stats_after = file_cache.cache_stats()
    assert stats_after["misses"] == len(files), (
        "subsequent sync reads should be hits, not new misses"
    )
    assert stats_after["hits"] == len(files)


def test_warm_cache_async_skips_already_cached(tmp_path: Path) -> None:
    f1 = _write(tmp_path, "a.py", "a\n")
    f2 = _write(tmp_path, "b.py", "b\n")

    file_cache.read_text_cached(f1)
    loaded = asyncio.run(file_cache.warm_cache_async([f1, f2]))

    assert loaded == 1, "f1 was already cached; only f2 should have been read"
    assert file_cache.cache_stats()["entries"] == 2


def test_warm_cache_async_swallows_oserror(tmp_path: Path) -> None:
    real = _write(tmp_path, "real.py", "x\n")
    missing = tmp_path / "does_not_exist.py"

    loaded = asyncio.run(file_cache.warm_cache_async([real, missing]))

    assert loaded == 1
    assert file_cache.cache_stats()["entries"] == 1


def test_clear_cache_resets_stats_and_entries(tmp_path: Path) -> None:
    f = _write(tmp_path, "a.py", "x\n")
    file_cache.read_text_cached(f)
    file_cache.read_text_cached(f)

    assert file_cache.cache_stats()["entries"] == 1

    file_cache.clear_cache()
    assert file_cache.cache_stats() == {"hits": 0, "misses": 0, "entries": 0}


def test_async_returns_unicode_replacement_on_invalid_bytes(
    tmp_path: Path,
) -> None:
    f = tmp_path / "bin.py"
    f.write_bytes(b"good\xff\xfeextra")

    text = asyncio.run(file_cache.read_text_cached_async(f))

    assert text.startswith("good")
    assert "extra" in text


def test_cache_models_behavioral_analyzer_read_pattern(tmp_path: Path) -> None:
    """End-to-end invariant: under the real analyzer's read pattern, every
    source file is loaded from disk exactly once.

    The behavioural analyzer reads each file in three places during a
    directory scan:

    1. ``warm_cache_async`` — concurrent prefetch into the cache.
    2. The call-graph build loop — sync ``read_text_cached`` per file.
    3. ``_analyze_file`` — sync ``read_text_cached`` per file again.

    With a working cache we expect: ``misses == N`` (one per file, all from
    step 1), ``hits == 2 * N`` (steps 2 and 3), ``entries == N``.
    """
    files = [_write(tmp_path, f"mod{i}.py", f"# module {i}\n") for i in range(5)]
    n = len(files)

    async def _drive() -> None:
        # Step 1: prefetch (mirrors the analyzer's directory-branch warm-up).
        loaded = await file_cache.warm_cache_async(files, concurrency=4)
        assert loaded == n

        # Step 2: call-graph build loop — sync reads.
        for f in files:
            assert file_cache.read_text_cached(f) == f"# module {f.stem[3:]}\n"

        # Step 3: _analyze_file — sync reads again on the same paths.
        for f in files:
            assert file_cache.read_text_cached(f) == f"# module {f.stem[3:]}\n"

    asyncio.run(_drive())

    stats = file_cache.cache_stats()
    assert stats["entries"] == n, f"expected {n} cached entries, got {stats}"
    assert stats["misses"] == n, (
        f"expected exactly one disk read per file (got {stats['misses']}); "
        "a higher number means the cache is bypassed by some call site"
    )
    assert stats["hits"] == 2 * n, (
        f"expected {2 * n} cache hits (2 per file from steps 2 + 3), "
        f"got {stats['hits']}"
    )


def test_cache_eliminates_redundant_reads_under_concurrent_warm(
    tmp_path: Path,
) -> None:
    """Even when warm_cache_async runs concurrently, the same path read by
    multiple coroutines is loaded from disk exactly once."""
    f = _write(tmp_path, "shared.py", "shared\n")

    async def _drive() -> None:
        await asyncio.gather(
            *(file_cache.warm_cache_async([f]) for _ in range(8))
        )

    asyncio.run(_drive())

    stats = file_cache.cache_stats()
    assert stats["entries"] == 1
    assert stats["misses"] == 1, (
        f"the same path was loaded {stats['misses']} times; warm should be "
        "idempotent across concurrent callers"
    )
