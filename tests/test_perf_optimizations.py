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

"""Unit tests covering the call-graph / AST / batching performance work.

These tests are intentionally hermetic: no LLM, no MCP server, no disk
fixtures. They directly exercise the data structures that changed so that
regressions in the new performance paths surface immediately.
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import AsyncMock

import pytest

from mcpscanner.core.static_analysis import ast_cache
from mcpscanner.core.static_analysis.interprocedural.call_graph_analyzer import (
    CallGraph,
    CallGraphAnalyzer,
)
from mcpscanner.core.static_analysis.interprocedural.treesitter_call_graph import (
    TSCallGraph,
)


# ---------------------------------------------------------------------------
# CallGraph adjacency / short-name index (item 1a/1b)
# ---------------------------------------------------------------------------


def _add_edge(g: CallGraph, caller: str, callee: str) -> None:
    """Helper that registers two functions and an edge between them."""
    g.add_function(caller.split("::")[1], object(), Path(caller.split("::")[0]))
    g.add_function(callee.split("::")[1], object(), Path(callee.split("::")[0]))
    g.add_call(caller, callee)


def test_callgraph_callees_uses_adjacency_index_o1():
    g = CallGraph()
    # Build a wide graph with many fanout edges, then assert lookup is bounded.
    for i in range(500):
        _add_edge(g, f"file_{i}.py::root", f"file_{i}.py::leaf_{i}")

    callees = g.get_callees("file_42.py::root")
    assert callees == ["file_42.py::leaf_42"]


def test_callgraph_dedupes_repeated_edges():
    """``add_call`` must be idempotent; AST visitors often re-emit edges."""
    g = CallGraph()
    g.add_function("a", object(), Path("x.py"))
    g.add_function("b", object(), Path("x.py"))
    for _ in range(10):
        g.add_call("x.py::a", "x.py::b")
    assert g.calls == [("x.py::a", "x.py::b")]
    assert g.get_callees("x.py::a") == ["x.py::b"]
    assert g.get_callers("x.py::b") == ["x.py::a"]


def test_callgraph_short_name_index_matches_method_and_dotted_form():
    g = CallGraph()
    g.add_function("Worker.process", object(), Path("svc.py"))
    g.add_function("helper", object(), Path("util.py"))

    # Bare method should resolve via the trailing-component shortcut.
    assert "svc.py::Worker.process" in g.get_functions_by_short_name("process")
    # Dotted form resolves via the full-name index.
    assert "svc.py::Worker.process" in g.get_functions_by_short_name(
        "Worker.process"
    )
    # Bare top-level function still resolvable.
    assert g.get_functions_by_short_name("helper") == ["util.py::helper"]


# ---------------------------------------------------------------------------
# CallGraphAnalyzer reachability cache + parameter flow (item 1c)
# ---------------------------------------------------------------------------


def _seed_analyzer_graph(analyzer: CallGraphAnalyzer) -> None:
    """Manually seed an analyzer's CallGraph; bypasses ``add_file``."""
    g = analyzer.call_graph
    for fn in [
        "a.py::entry",
        "a.py::helper",
        "b.py::deep",
        "c.py::leaf",
    ]:
        g.add_function(fn.split("::")[1], object(), Path(fn.split("::")[0]))
    g.mcp_entry_points.add("a.py::entry")
    g.add_call("a.py::entry", "a.py::helper")
    g.add_call("a.py::helper", "b.py::deep")
    g.add_call("b.py::deep", "c.py::leaf")


def test_reachable_set_is_cached_per_entry_point():
    analyzer = CallGraphAnalyzer()
    _seed_analyzer_graph(analyzer)

    first = analyzer.get_reachable_functions("a.py::entry")
    # Mutating the underlying graph after caching should not affect
    # subsequent lookups for the same entry point.
    analyzer.call_graph.add_function("ghost", object(), Path("z.py"))
    analyzer.call_graph.add_call("c.py::leaf", "z.py::ghost")
    second = analyzer.get_reachable_functions("a.py::entry")

    assert set(first) == set(second) == {
        "a.py::entry",
        "a.py::helper",
        "b.py::deep",
        "c.py::leaf",
    }
    assert "z.py::ghost" not in second  # cache, not a re-walk


def test_analyze_parameter_flow_uses_callee_index_and_reports_cross_file():
    analyzer = CallGraphAnalyzer()
    _seed_analyzer_graph(analyzer)

    flow = analyzer.analyze_parameter_flow_across_files(
        "a.py::entry", ["arg"]
    )
    assert "a.py::entry" in flow["reachable_functions"]
    assert flow["param_influenced_functions"]  # at least the helper
    cross_file = {(f["from_file"], f["to_file"]) for f in flow["cross_file_flows"]}
    assert ("a.py", "b.py") in cross_file
    assert ("b.py", "c.py") in cross_file
    assert flow["total_files_involved"] == 3


# ---------------------------------------------------------------------------
# TSCallGraph parity (item 1a/1b for tree-sitter)
# ---------------------------------------------------------------------------


def test_tscallgraph_indices_mirror_python_callgraph():
    g = TSCallGraph()
    g.add_function("Worker.run", object(), Path("a.go"))
    g.add_function("helper", object(), Path("b.go"))
    g.add_call("a.go::Worker.run", "b.go::helper")
    # Repeated edge must dedupe.
    g.add_call("a.go::Worker.run", "b.go::helper")

    assert g.calls == [("a.go::Worker.run", "b.go::helper")]
    assert g.get_callees("a.go::Worker.run") == ["b.go::helper"]
    assert g.get_callers("b.go::helper") == ["a.go::Worker.run"]
    assert "a.go::Worker.run" in g.get_functions_by_short_name("run")
    assert "a.go::Worker.run" in g.get_functions_by_short_name("Worker.run")


# ---------------------------------------------------------------------------
# AST cache (item 1f)
# ---------------------------------------------------------------------------


def test_ast_cache_returns_same_object_for_identical_source():
    ast_cache.clear_ast_cache()
    src = "def foo():\n    return 42\n"
    a = ast_cache.get_python_ast(src, "/tmp/foo.py")
    b = ast_cache.get_python_ast(src, "/tmp/foo.py")
    assert a is b
    stats = ast_cache.ast_cache_stats()
    assert stats["hits"] == 1
    assert stats["misses"] == 1


def test_ast_cache_different_sources_yield_different_objects():
    ast_cache.clear_ast_cache()
    a = ast_cache.get_python_ast("x = 1\n", "/tmp/a.py")
    b = ast_cache.get_python_ast("x = 2\n", "/tmp/a.py")  # same path, diff content
    assert a is not b
    stats = ast_cache.ast_cache_stats()
    assert stats["misses"] == 2


def test_ast_cache_eviction_obeys_size_budget(monkeypatch):
    """Older entries should be dropped once we exceed the configured cap."""
    ast_cache.clear_ast_cache()
    monkeypatch.setattr(ast_cache, "_AST_CACHE_MAX_ENTRIES", 4)
    for i in range(8):
        ast_cache.get_python_ast(f"x = {i}\n", f"/tmp/{i}.py")
    stats = ast_cache.ast_cache_stats()
    assert stats["entries"] <= 4
    assert stats["evictions"] >= 4


# ---------------------------------------------------------------------------
# AlignmentOrchestrator: token-aware packer + slot-level retry
# (items 2a + 2d)
# ---------------------------------------------------------------------------


class _FakeFunctionContext:
    """Stand-in for ``FunctionContext`` that ``_pack_batches`` understands.

    Keeps the test free of the real dataclass's many required fields while
    exposing the attributes the packer actually reads.
    """

    def __init__(self, name: str, source: str = "") -> None:
        self.name = name
        self.source = source


def _make_orchestrator():
    """Construct an orchestrator with stubbed external dependencies.

    The packer logic is independent of the LLM client, so we keep that as
    an ``AsyncMock`` and never actually invoke it.
    """
    from mcpscanner.core.analyzers.behavioral.alignment.alignment_orchestrator import (
        AlignmentOrchestrator,
    )

    orch = AlignmentOrchestrator.__new__(AlignmentOrchestrator)
    orch.logger = AsyncMock()
    orch.logger.debug = lambda *a, **k: None
    orch.logger.info = lambda *a, **k: None
    orch.logger.warning = lambda *a, **k: None
    orch.logger.error = lambda *a, **k: None
    orch.stats = {"total_analyzed": 0, "mismatches_detected": 0, "no_mismatch": 0}
    return orch


def test_pack_batches_respects_batch_size_cap():
    orch = _make_orchestrator()
    fcs = [_FakeFunctionContext(f"f{i}", source="x" * 100) for i in range(7)]
    batches = orch._pack_batches(fcs, batch_size=3, prompt_budget_chars=10_000)
    assert [len(b) for b in batches] == [3, 3, 1]


def test_pack_batches_respects_prompt_budget_when_smaller_than_count():
    orch = _make_orchestrator()
    # Each function: 600 overhead + min(2000, len(source)). Source 1500
    # chars → 2100 chars per function.
    fcs = [_FakeFunctionContext(f"f{i}", source="y" * 1500) for i in range(5)]
    batches = orch._pack_batches(fcs, batch_size=10, prompt_budget_chars=5000)
    # 2100 + 2100 = 4200 (fits), +2100 = 6300 (over) → batches of 2.
    assert all(len(b) <= 2 for b in batches)
    assert sum(len(b) for b in batches) == 5


def test_pack_batches_oversized_function_still_packed_alone():
    orch = _make_orchestrator()
    fcs = [_FakeFunctionContext("big", source="z" * 100_000)]
    batches = orch._pack_batches(fcs, batch_size=5, prompt_budget_chars=1000)
    assert batches == [fcs]  # not dropped


# ---------------------------------------------------------------------------
# Response validator: padding sentinel for slot-level retry (item 2d)
# ---------------------------------------------------------------------------


def test_validator_marks_padded_slots_with_sentinel():
    from mcpscanner.core.analyzers.behavioral.alignment.alignment_response_validator import (
        AlignmentResponseValidator,
    )

    v = AlignmentResponseValidator()
    response = (
        '[{"function_index":0,"function_name":"a","mismatch_detected":false}]'
    )
    out = v.validate_batch(response, expected_count=3)
    assert out is not None
    assert len(out) == 3
    assert out[0].get("function_name") == "a"
    assert out[0].get("_padded") is not True  # real result
    # Padded entries must carry the sentinel so the orchestrator's
    # slot-level retry can target them specifically.
    assert out[1].get("_padded") is True
    assert out[2].get("_padded") is True


# ---------------------------------------------------------------------------
# Scanner._gather_bounded throttling (item 4)
# ---------------------------------------------------------------------------


def _build_dummy_scanner(tool_concurrency: int):
    """Construct a Scanner without going through ``__init__`` (no Config needed)."""
    from mcpscanner.core.scanner import Scanner

    s = Scanner.__new__(Scanner)
    s._tool_concurrency = tool_concurrency
    return s


@pytest.mark.asyncio
async def test_gather_bounded_unbounded_runs_everything_concurrently():
    s = _build_dummy_scanner(tool_concurrency=0)
    in_flight = 0
    peak = 0
    lock = asyncio.Lock()

    async def task():
        nonlocal in_flight, peak
        async with lock:
            in_flight += 1
            peak = max(peak, in_flight)
        await asyncio.sleep(0.05)
        async with lock:
            in_flight -= 1
        return 1

    results = await s._gather_bounded([task() for _ in range(8)])
    assert results == [1] * 8
    assert peak == 8  # default behaviour: full unbounded fan-out


@pytest.mark.asyncio
async def test_gather_bounded_respects_concurrency_limit():
    s = _build_dummy_scanner(tool_concurrency=3)
    in_flight = 0
    peak = 0
    lock = asyncio.Lock()

    async def task():
        nonlocal in_flight, peak
        async with lock:
            in_flight += 1
            peak = max(peak, in_flight)
        await asyncio.sleep(0.05)
        async with lock:
            in_flight -= 1
        return 1

    results = await s._gather_bounded([task() for _ in range(10)])
    assert results == [1] * 10
    assert peak <= 3


@pytest.mark.asyncio
async def test_gather_bounded_propagates_exceptions_by_default():
    s = _build_dummy_scanner(tool_concurrency=2)

    async def failing():
        raise RuntimeError("boom")

    async def ok():
        return "ok"

    with pytest.raises(RuntimeError):
        await s._gather_bounded([ok(), failing(), ok()])
