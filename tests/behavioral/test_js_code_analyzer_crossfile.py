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

"""Cross-file capability extraction wiring for JSBehavioralCodeAnalyzer."""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from mcpscanner.core.analyzers.behavioral import js_code_analyzer as jmod
from mcpscanner.core.static_analysis import NativeAnalyzer


class _FakeConfig:
    def __init__(self, llm_provider_api_key: str = "test-key"):
        self.llm_provider_api_key = llm_provider_api_key
        self.llm_model = "gpt-4o-mini"
        self.llm_base_url = ""
        self.llm_api_version = ""


GRAPH_TOOLS_INDEX = """\
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { api } from "./graph-endpoints.js";

const server = new McpServer({ name: "graph", version: "1.0" });

for (const tool of api.endpoints) {
  server.tool(
    tool.alias,
    tool.description,
    tool.schema,
    {},
    async (params) => ({ content: [{ type: "text", text: "ok" }] }),
  );
}
"""

GRAPH_ENDPOINTS_MODULE = """\
export const api = {
  endpoints: [
    { alias: "list-mail", description: "List mail", schema: {} },
    { alias: "get-calendar", description: "Get calendar", schema: {} },
  ],
};
"""


def test_build_directory_call_graphs_expands_imported_endpoint_aliases(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Directory call graphs must resolve ``tool.alias`` from sibling modules."""
    index_path = tmp_path / "graph-tools.ts"
    endpoints_path = tmp_path / "graph-endpoints.ts"
    index_path.write_text(GRAPH_TOOLS_INDEX)
    endpoints_path.write_text(GRAPH_ENDPOINTS_MODULE)

    monkeypatch.setattr(jmod, "AlignmentOrchestrator", MagicMock())
    analyzer = jmod.JSBehavioralCodeAnalyzer(_FakeConfig())
    files = analyzer._find_js_files(str(tmp_path))
    call_graphs = analyzer._build_directory_call_graphs(files)

    assert "typescript" in call_graphs
    caps = NativeAnalyzer(
        GRAPH_TOOLS_INDEX, str(index_path)
    ).extract_mcp_capability_contexts(
        cross_file_analyzer=call_graphs["typescript"]
    )
    names = {c.name for c in caps}
    assert "list-mail" in names, names
    assert "get-calendar" in names, names


def test_analyze_directory_passes_cross_file_analyzer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``analyze(directory)`` must wire cross-file graphs into extraction."""
    index_path = tmp_path / "graph-tools.ts"
    endpoints_path = tmp_path / "graph-endpoints.ts"
    index_path.write_text(GRAPH_TOOLS_INDEX)
    endpoints_path.write_text(GRAPH_ENDPOINTS_MODULE)

    monkeypatch.setattr(jmod, "AlignmentOrchestrator", MagicMock())

    cross_file_seen: list[bool] = []
    original_extract = NativeAnalyzer.extract_mcp_capability_contexts

    def _spy_extract(self, cross_file_analyzer=None):
        cross_file_seen.append(cross_file_analyzer is not None)
        return original_extract(self, cross_file_analyzer=cross_file_analyzer)

    monkeypatch.setattr(
        NativeAnalyzer, "extract_mcp_capability_contexts", _spy_extract
    )

    analyzer = jmod.JSBehavioralCodeAnalyzer(_FakeConfig())
    asyncio.run(analyzer.analyze(str(tmp_path), {}))

    assert cross_file_seen, "expected at least one extraction pass"
    assert any(cross_file_seen), "cross_file_analyzer was never passed"


def test_build_directory_call_graphs_enforces_aggregate_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Untrusted packages must not load unbounded files into call-graph memory."""
    for idx in range(jmod._JS_CALL_GRAPH_MAX_FILES + 5):
        path = tmp_path / f"file-{idx}.ts"
        path.write_text(
            "export const x = 1;\n"
            if idx
            else 'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\n'
            'const server = new McpServer({ name: "demo", version: "1.0" });\n'
        )

    monkeypatch.setattr(jmod, "AlignmentOrchestrator", MagicMock())
    analyzer = jmod.JSBehavioralCodeAnalyzer(_FakeConfig())
    files = analyzer._find_js_files(str(tmp_path))
    call_graphs = analyzer._build_directory_call_graphs(files)

    assert analyzer._call_graph_partial is True
    assert "typescript" in call_graphs
    assert len(call_graphs["typescript"].files) <= jmod._JS_CALL_GRAPH_MAX_FILES


# ---------------------------------------------------------------------------
# Discovery and call-graph budgets.
#
# File and byte budgets bound how much source is read, but not how much that
# source expands into, nor how long the walk to find it takes. These pin the
# remaining axes so a hostile package cannot exhaust CPU or memory while the
# result still claims to be complete.
# ---------------------------------------------------------------------------


def test_find_js_files_caps_matched_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Discovery stops at the file cap and records partial coverage."""
    monkeypatch.setattr(jmod, "_JS_MAX_FILES", 5)
    monkeypatch.setattr(jmod, "AlignmentOrchestrator", MagicMock())
    for idx in range(20):
        (tmp_path / f"f{idx}.ts").write_text("export const x = 1;\n")

    analyzer = jmod.JSBehavioralCodeAnalyzer(_FakeConfig())
    files = analyzer._find_js_files(str(tmp_path))

    assert len(files) <= 5, len(files)
    assert analyzer._call_graph_partial is True


def test_find_js_files_caps_directory_entries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A large tree holding few matches still costs a bounded walk."""
    monkeypatch.setattr(jmod, "_JS_MAX_DIR_ENTRIES", 10)
    monkeypatch.setattr(jmod, "AlignmentOrchestrator", MagicMock())
    for idx in range(50):
        (tmp_path / f"pad{idx}.txt").write_text("x")

    analyzer = jmod.JSBehavioralCodeAnalyzer(_FakeConfig())
    analyzer._find_js_files(str(tmp_path))

    assert analyzer._call_graph_partial is True


def test_find_js_files_clean_tree_is_not_partial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A tree inside every budget must not be reported as partial."""
    monkeypatch.setattr(jmod, "AlignmentOrchestrator", MagicMock())
    (tmp_path / "only.ts").write_text("export const x = 1;\n")

    analyzer = jmod.JSBehavioralCodeAnalyzer(_FakeConfig())
    files = analyzer._find_js_files(str(tmp_path))

    assert len(files) == 1
    assert analyzer._call_graph_partial is False


def test_call_graph_ast_budget_marks_partial(monkeypatch: pytest.MonkeyPatch) -> None:
    """Cumulative AST size is capped even when byte budgets pass."""
    from mcpscanner.core.static_analysis.interprocedural import (
        treesitter_call_graph as tsmod,
    )

    monkeypatch.setattr(tsmod, "MAX_AST_NODES", 5)
    analyzer = tsmod.TreeSitterCallGraphAnalyzer("typescript")
    accepted = analyzer.add_file(
        Path("big.ts"), "function a(){ b(); c(); d(); e(); f(); }\n"
    )

    assert accepted is False
    assert analyzer.budget_exceeded is True


def test_call_graph_edge_budget_marks_partial(monkeypatch: pytest.MonkeyPatch) -> None:
    """Densely connected sources stop adding edges once the cap is hit."""
    from mcpscanner.core.static_analysis.interprocedural import (
        treesitter_call_graph as tsmod,
    )

    monkeypatch.setattr(tsmod, "MAX_CALL_EDGES", 3)
    analyzer = tsmod.TreeSitterCallGraphAnalyzer("typescript")
    body = "".join(f"  callee{i}();\n" for i in range(40))
    analyzer.add_file(Path("dense.ts"), f"function entry() {{\n{body}}}\n")
    graph = analyzer.build_call_graph()

    assert analyzer.budget_exceeded is True
    assert len(graph.calls) <= 3 + 1, len(graph.calls)


def test_release_parsed_sources_frees_trees_but_keeps_graph() -> None:
    """Releasing retained source must not invalidate the built graph."""
    from mcpscanner.core.static_analysis.interprocedural import (
        treesitter_call_graph as tsmod,
    )

    analyzer = tsmod.TreeSitterCallGraphAnalyzer("typescript")
    analyzer.add_file(Path("a.ts"), "export function helper(x){ return x; }\n")
    analyzer.add_file(
        Path("b.ts"),
        "import {helper} from './a';\nfunction entry(y){ return helper(y); }\n",
    )
    graph = analyzer.build_call_graph()
    functions_before = len(graph.functions)

    analyzer.release_parsed_sources()

    assert analyzer.files == {}
    assert len(graph.functions) == functions_before
    # Function nodes keep their own tree alive, so they stay usable.
    assert next(iter(graph.functions.values())).type


def test_call_graph_adjacency_matches_edge_list() -> None:
    """The callee/caller indexes must agree with the raw edge list."""
    from mcpscanner.core.static_analysis.interprocedural import (
        treesitter_call_graph as tsmod,
    )

    graph = tsmod.TSCallGraph()
    graph.add_call("a", "b")
    graph.add_call("a", "c")
    graph.add_call("d", "b")

    assert graph.get_callees("a") == ["b", "c"]
    assert graph.get_callers("b") == ["a", "d"]
    assert graph.get_callees("zzz") == []
    assert sorted(graph.calls) == [("a", "b"), ("a", "c"), ("d", "b")]
