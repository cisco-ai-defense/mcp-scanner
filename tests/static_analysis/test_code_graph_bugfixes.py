# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for code-graph layer bugfixes."""

from __future__ import annotations

from pathlib import Path

from mcpscanner.core.static_analysis.context_extractor import FunctionContext
from mcpscanner.core.static_analysis.graph.builder import CodeGraphBuilder
from mcpscanner.core.static_analysis.graph.integration import (
    _paths_refer_to_same_file,
    partition_functions_by_graph,
    resolve_entry_id,
)
from mcpscanner.core.static_analysis.graph.models import CodeEdge, CodeGraph, CodeNode, Relation
from mcpscanner.core.static_analysis.graph.sink_analyzer import SinkAnalyzer
from mcpscanner.core.static_analysis.interprocedural.call_graph_analyzer import (
    CallGraphAnalyzer,
)


def test_build_call_graph_is_idempotent() -> None:
    src = (
        "from mcp.server import Server\n"
        "mcp = Server('x')\n"
        "@mcp.tool()\n"
        "def hello():\n"
        "    open('/tmp/x').read()\n"
    )
    path = Path("/tmp/mcp_graph_idempotent_test.py")
    path.write_text(src, encoding="utf-8")
    cga = CallGraphAnalyzer()
    cga.add_file(path, src)
    n1 = len(cga.build_call_graph().calls)
    n2 = len(cga.build_call_graph().calls)
    assert n1 == n2
    assert n1 > 0


def test_merge_graphs_dedupes_edges() -> None:
    builder = CodeGraphBuilder()
    left = CodeGraph(language="python")
    right = CodeGraph(language="python")
    left.add_node(
        CodeNode(
            node_id="/a.py::f",
            label="f",
            source_file="/a.py",
            language="python",
        )
    )
    from mcpscanner.core.static_analysis.graph.models import Provenance

    edge = CodeEdge(
        source="/a.py::f",
        target="external::open",
        relation=Relation.CALLS,
        provenance=Provenance.INFERRED,
    )
    left.edges.append(edge)
    right.edges.append(edge)
    builder._merge_graphs(left, right)
    assert len(left.edges) == 1


def test_sink_analyzer_skips_entry_node_label() -> None:
    graph = CodeGraph(language="python")
    entry = "/tmp/t.py::open"
    graph.add_node(
        CodeNode(
            node_id=entry,
            label="open",
            source_file="/tmp/t.py",
            language="python",
            is_mcp_entry=True,
        )
    )
    graph.entry_points.add(entry)
    result = SinkAnalyzer(graph).analyze_entry(entry)
    assert not any(hit.sink_id == entry for hit in result.hits)


def test_partition_marks_unresolved_entry() -> None:
    graph = CodeGraph(language="python")
    ctx = FunctionContext(
        name="missing_tool",
        decorator_types=["tool"],
        imports=[],
        function_calls=[],
        assignments=[],
        control_flow={},
        parameter_flows=[],
        constants={},
        variable_dependencies={},
        has_file_operations=False,
        has_network_operations=False,
        has_subprocess_calls=False,
        has_eval_exec=False,
        has_dangerous_imports=False,
    )
    _, needs_llm = partition_functions_by_graph([ctx], graph, "/no/such/file.py")
    assert needs_llm == [ctx]
    assert ctx.dataflow_summary.get("code_graph_status") == "entry_unresolved"


def test_resolve_entry_id_macos_private_var_path(tmp_path: Path) -> None:
    sample = tmp_path / "server.py"
    sample.write_text("def tool_alpha(): pass\n", encoding="utf-8")
    resolved = sample.resolve()
    node_id = f"{resolved}::tool_alpha"
    graph = CodeGraph(language="python")
    graph.add_node(
        CodeNode(
            node_id=node_id,
            label="tool_alpha",
            source_file=str(resolved),
            language="python",
            is_mcp_entry=True,
        )
    )
    graph.entry_points.add(node_id)

    if str(resolved).startswith("/private/"):
        alt = Path("/" + str(resolved).removeprefix("/private/"))
        if alt.is_file():
            assert resolve_entry_id(graph, str(alt), "tool_alpha") == node_id
    elif str(resolved).startswith("/var/"):
        alt = Path(f"/private{resolved}")
        if alt.is_file():
            assert resolve_entry_id(graph, str(alt), "tool_alpha") == node_id

    assert _paths_refer_to_same_file(resolved, resolved)
