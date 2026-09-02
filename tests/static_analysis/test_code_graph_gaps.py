# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Extended graph layer tests for Graphify-parity gaps."""

from __future__ import annotations

from pathlib import Path

from mcpscanner.core.static_analysis.context_extractor import FunctionContext
from mcpscanner.core.static_analysis.graph import (
    CFGFusionEngine,
    ClassicDataflowEngine,
    CodeGraph,
    CodeGraphBuilder,
    CodeNode,
    InterproceduralTaintAnalyzer,
    Provenance,
    Relation,
    populate_taint_fields,
)
from mcpscanner.core.static_analysis.graph.resolver import CrossFileSymbolResolver


def _ctx(**overrides):
    """Create a default function context for graph and taint analysis tests.
    
    Keyword arguments override the default context fields.
    
    Returns:
    	FunctionContext: A configured function context with an MCP tool name and file-operation parameter flow.
    """
    base = dict(
        name="tool",
        decorator_types=["@mcp.tool"],
        imports=[],
        function_calls=[],
        assignments=[],
        control_flow={},
        parameter_flows=[
            {
                "parameter": "path",
                "operations": [{"type": "function_call", "function": "os.remove", "line": 3}],
                "reaches_external": True,
            }
        ],
        constants={},
        variable_dependencies={},
        has_file_operations=True,
        has_network_operations=False,
        has_subprocess_calls=False,
        has_eval_exec=False,
        has_dangerous_imports=False,
    )
    base.update(overrides)
    return FunctionContext(**base)


class TestGraphGaps:
    def test_code_graph_roundtrip(self):
        graph = CodeGraph(language="python")
        graph.add_node(
            CodeNode(
                node_id="/tmp/a.py::delete_file",
                label="delete_file",
                source_file="/tmp/a.py",
                language="python",
                is_mcp_entry=True,
            )
        )
        restored = CodeGraph.from_dict(graph.to_dict())
        assert restored.nodes["/tmp/a.py::delete_file"].is_mcp_entry

    def test_populate_taint_fields(self):
        ctx = _ctx()
        populate_taint_fields(ctx)
        assert ctx.taint_sources
        assert ctx.taint_sinks
        assert ctx.taint_flows

    def test_resolver_dynamic_dispatch(self):
        resolver = CrossFileSymbolResolver({}, language="javascript")
        resolved, provenance, confidence, context = resolver.resolve_callee(
            "/tmp/a.js::handler",
            "obj[method]()",
            set(),
        )
        assert resolved.startswith("external::")
        assert context == "dynamic_dispatch"
        assert confidence == 0.5

    def test_resolver_dynamic_dispatch_literal_bracket(self, tmp_path: Path) -> None:
        util = tmp_path / "util.ts"
        server = tmp_path / "server.ts"
        util.write_text(
            """
export class FileWorker {
  run(target: string): void {
    require("fs").unlinkSync(target);
  }
}
""".strip()
            + "\n",
            encoding="utf-8",
        )
        server.write_text(
            """
import { FileWorker } from "./util";

export function handler(path: string): void {
  const worker = new FileWorker();
  worker["run"](path);
}
""".strip()
            + "\n",
            encoding="utf-8",
        )

        builder = CodeGraphBuilder()
        builder.add_path(util)
        builder.add_path(server)
        built = builder.build()

        handler_id = next(nid for nid, n in built.nodes.items() if n.label == "handler")
        run_id = next(
            nid
            for nid, n in built.nodes.items()
            if n.label == "FileWorker.run" or n.label.endswith(".run")
        )
        call_edges = [
            e
            for e in built.edges
            if e.source == handler_id
            and e.relation == Relation.CALLS
            and e.target == run_id
        ]
        assert call_edges
        assert call_edges[0].context.startswith("semantic_bracket_literal")
        assert call_edges[0].provenance == Provenance.EXTRACTED

    def test_parse_dynamic_call_ts_cast_bracket(self) -> None:
        from mcpscanner.core.static_analysis.graph.dynamic_dispatch import parse_dynamic_call

        assert parse_dynamic_call("(worker as any)[method]") == (
            "worker",
            None,
            "bracket_variable",
        )
        assert parse_dynamic_call("(worker as FileWorker)['run']") == (
            "worker",
            "run",
            "bracket_literal",
        )

    def test_resolver_dynamic_dispatch_cast_bracket_cross_file(
        self, tmp_path: Path
    ) -> None:
        workers = tmp_path / "workers.ts"
        server = tmp_path / "server.ts"
        workers.write_text(
            """
import fs from "fs";

export class FileWorker {
  run(target: string): void {
    fs.unlinkSync(target);
  }
}
""".strip()
            + "\n",
            encoding="utf-8",
        )
        server.write_text(
            """
import { FileWorker } from "./workers";

function factory() {
  return new FileWorker();
}

function getMethod() {
  return "run";
}

export function handler(path: string): void {
  const worker = factory();
  const method = getMethod();
  (worker as any)[method](path);
}
""".strip()
            + "\n",
            encoding="utf-8",
        )

        builder = CodeGraphBuilder()
        builder.add_path(workers)
        builder.add_path(server)
        built = builder.build()

        handler_id = next(nid for nid, n in built.nodes.items() if n.label == "handler")
        run_id = next(
            nid
            for nid, n in built.nodes.items()
            if n.label == "FileWorker.run" or n.label.endswith(".run")
        )
        call_edges = [
            e
            for e in built.edges
            if e.source == handler_id
            and e.relation == Relation.CALLS
            and e.target == run_id
        ]
        assert call_edges
        assert call_edges[0].context.startswith("fixpoint_r0:const_prop_semantic_bracket_variable")

    def test_sink_matches_require_fs_chain(self) -> None:
        from mcpscanner.core.static_analysis.graph.sink_analyzer import _match_sink, _sink_lookup

        sinks = _sink_lookup("typescript")
        assert _match_sink("require('fs').unlinkSync", sinks) == ("file", "fs.unlinksync")

    def test_treesitter_mcp_entry_points(self, tmp_path: Path) -> None:
        sample = tmp_path / "server.ts"
        sample.write_text(
            """
@mcp.tool()
export function delete_file(path: string): void {}

function helper(path: string): void {}
""".strip()
            + "\n",
            encoding="utf-8",
        )
        builder = CodeGraphBuilder()
        builder.add_path(sample)
        built = builder.build()

        delete_id = next(
            nid for nid, n in built.nodes.items() if n.label == "delete_file"
        )
        helper_id = next(nid for nid, n in built.nodes.items() if n.label == "helper")
        assert built.nodes[delete_id].is_mcp_entry
        assert delete_id in built.entry_points
        assert not built.nodes[helper_id].is_mcp_entry

    def test_resolver_dynamic_dispatch_getattr_python(self, tmp_path: Path) -> None:
        sample = tmp_path / "server.py"
        sample.write_text(
            """
class FileWorker:
    def run(self, target: str) -> None:
        import os
        os.remove(target)

def handler(path: str) -> None:
    worker = FileWorker()
    getattr(worker, "run")(path)
""".strip()
            + "\n",
            encoding="utf-8",
        )
        builder = CodeGraphBuilder()
        builder.add_path(sample)
        built = builder.build()

        handler_id = next(nid for nid, n in built.nodes.items() if n.label == "handler")
        run_id = next(
            nid
            for nid, n in built.nodes.items()
            if n.label == "FileWorker.run" or n.label.endswith(".run")
        )
        call_edges = [
            e
            for e in built.edges
            if e.source == handler_id
            and e.relation == Relation.CALLS
            and e.target == run_id
        ]
        assert call_edges
        assert "getattr" in (call_edges[0].context or "") or "semantic" in (call_edges[0].context or "")
        assert call_edges[0].provenance == Provenance.EXTRACTED

    def test_const_prop_dynamic_bracket(self, tmp_path: Path) -> None:
        sample = tmp_path / "server.ts"
        sample.write_text(
            """
class FileWorker {
  run(target: string): void {
    require("fs").unlinkSync(target);
  }
}

export function handler(path: string): void {
  const worker = new FileWorker();
  const m = "run";
  worker[m](path);
}
""".strip()
            + "\n",
            encoding="utf-8",
        )
        builder = CodeGraphBuilder()
        builder.add_path(sample)
        built = builder.build()

        handler_id = next(nid for nid, n in built.nodes.items() if n.label == "handler")
        run_edges = [
            e
            for e in built.edges
            if e.source == handler_id
            and e.relation == Relation.CALLS
            and e.target.split("::")[-1].endswith(".run")
        ]
        assert run_edges
        assert "const_prop" in (run_edges[0].context or "")

    def test_alias_points_to_dynamic_dispatch(self, tmp_path: Path) -> None:
        sample = tmp_path / "server.ts"
        sample.write_text(
            """
class FileWorker {
  run(target: string): void {
    require("fs").unlinkSync(target);
  }
}

export function handler(path: string): void {
  const worker = new FileWorker();
  const alias = worker;
  alias["run"](path);
}
""".strip()
            + "\n",
            encoding="utf-8",
        )
        builder = CodeGraphBuilder()
        builder.add_path(sample)
        built = builder.build()

        handler_id = next(nid for nid, n in built.nodes.items() if n.label == "handler")
        run_edges = [
            e
            for e in built.edges
            if e.source == handler_id
            and e.relation == Relation.CALLS
            and "run" in built.nodes[e.target].label
        ]
        assert run_edges

    def test_virtual_dispatch_multi_target_edges(self, tmp_path: Path) -> None:
        sample = tmp_path / "server.ts"
        sample.write_text(
            """
class WorkerA {
  run(target: string): void {
    require("fs").unlinkSync(target);
  }
}

class WorkerB {
  run(target: string): void {
    require("child_process").exec(target);
  }
}

export function handler(path: string, pickA: boolean): void {
  const worker = pickA ? new WorkerA() : new WorkerB();
  const method = "run";
  worker[method](path);
}
""".strip()
            + "\n",
            encoding="utf-8",
        )
        builder = CodeGraphBuilder()
        builder.add_path(sample)
        built = builder.build()

        handler_id = next(nid for nid, n in built.nodes.items() if n.label == "handler")
        run_edges = [
            e
            for e in built.edges
            if e.source == handler_id
            and e.relation == Relation.CALLS
            and e.target.split("::")[-1].endswith(".run")
        ]
        assert len(run_edges) >= 2

    def test_cfg_fusion_maps_argument_to_callee_param(self, tmp_path: Path) -> None:
        sample = tmp_path / "server.py"
        sample.write_text(
            """
import os

def helper(target: str) -> None:
    os.remove(target)

def delete_file(path: str) -> None:
    helper(path)
""".strip()
            + "\n",
            encoding="utf-8",
        )
        graph = CodeGraphBuilder()
        graph.add_path(sample)
        built = graph.build()

        entry = next(nid for nid, n in built.nodes.items() if n.label == "delete_file")
        helper = next(nid for nid, n in built.nodes.items() if n.label == "helper")
        call_edge = next(
            e for e in built.edges if e.source == entry and e.target == helper
        )

        bindings = CFGFusionEngine(built).bindings_for_edge(call_edge, {"path"})
        assert bindings
        assert bindings[0].caller_taint == "path"
        assert bindings[0].callee_param == "target"
        assert bindings[0].provenance == Provenance.EXTRACTED

        taint = InterproceduralTaintAnalyzer(built).analyze_entry(entry)
        assert any(step.parameter == "target" for step in taint.flows)

    def test_semantic_method_resolution(self, tmp_path: Path) -> None:
        util = tmp_path / "util.ts"
        server = tmp_path / "server.ts"
        util.write_text(
            """
export class FileWorker {
  run(target: string): void {
    require("fs").unlinkSync(target);
  }
}
""".strip()
            + "\n",
            encoding="utf-8",
        )
        server.write_text(
            """
import { FileWorker } from "./util";

export function handler(path: string): void {
  const worker = new FileWorker();
  worker.run(path);
}
""".strip()
            + "\n",
            encoding="utf-8",
        )

        builder = CodeGraphBuilder()
        builder.add_path(util)
        builder.add_path(server)
        built = builder.build()

        handler_id = next(nid for nid, n in built.nodes.items() if n.label == "handler")
        run_id = next(
            nid
            for nid, n in built.nodes.items()
            if n.label == "FileWorker.run" or n.label.endswith(".run")
        )
        call_edges = [
            e for e in built.edges if e.source == handler_id and e.relation == Relation.CALLS
        ]
        assert any(e.target == run_id for e in call_edges)

    def test_ts_cfg_fusion_maps_argument_to_callee_param(self, tmp_path: Path) -> None:
        sample = tmp_path / "server.ts"
        sample.write_text(
            """
function helper(target: string): void {
  require("fs").unlinkSync(target);
}

function handler(path: string): void {
  helper(path);
}
""".strip()
            + "\n",
            encoding="utf-8",
        )
        builder = CodeGraphBuilder()
        builder.add_path(sample)
        built = builder.build()

        entry = next(nid for nid, n in built.nodes.items() if n.label == "handler")
        helper = next(nid for nid, n in built.nodes.items() if n.label == "helper")
        call_edge = next(
            e for e in built.edges if e.source == entry and e.target == helper
        )

        bindings = CFGFusionEngine(built).bindings_for_edge(call_edge, {"path"})
        assert bindings
        assert bindings[0].caller_taint == "path"
        assert bindings[0].callee_param == "target"
        assert bindings[0].provenance == Provenance.EXTRACTED

    def test_disk_graph_cache_persists_partials(self, tmp_path: Path) -> None:
        from mcpscanner.core.static_analysis.graph.cache import CodeGraphCache

        cache_dir = tmp_path / "graph-cache"
        cache = CodeGraphCache(cache_dir=cache_dir)
        graph = CodeGraph(language="python")
        graph.add_node(
            CodeNode(
                node_id="/tmp/a.py::tool",
                label="tool",
                source_file="/tmp/a.py",
                language="python",
            )
        )
        cache.put("/tmp/a.py", "def tool(): pass", graph)

        reloaded = CodeGraphCache(cache_dir=cache_dir)
        hit = reloaded.get("/tmp/a.py", "def tool(): pass")
        assert hit is not None
        assert "/tmp/a.py::tool" in hit.nodes
        assert reloaded.get("/tmp/a.py", "def other(): pass") is None

    def test_barrel_reexport_resolves_through_index(self, tmp_path: Path) -> None:
        util = tmp_path / "util.ts"
        barrel = tmp_path / "index.ts"
        server = tmp_path / "server.ts"
        util.write_text(
            """
export function helper(target: string): void {
  require("fs").unlinkSync(target);
}
""".strip()
            + "\n",
            encoding="utf-8",
        )
        barrel.write_text('export { helper } from "./util";\n', encoding="utf-8")
        server.write_text(
            """
import { helper } from "./index";

export function handler(path: string): void {
  helper(path);
}
""".strip()
            + "\n",
            encoding="utf-8",
        )

        builder = CodeGraphBuilder()
        builder.add_path(util)
        builder.add_path(barrel)
        builder.add_path(server)
        built = builder.build()

        handler_id = next(nid for nid, n in built.nodes.items() if n.label == "handler")
        helper_id = next(nid for nid, n in built.nodes.items() if n.label == "helper")
        call_edges = [
            e
            for e in built.edges
            if e.source == handler_id
            and e.relation == Relation.CALLS
            and e.target == helper_id
        ]
        assert call_edges
        assert call_edges[0].context in {"barrel_reexport", "import_symbol", None}

    def test_export_star_resolves_through_barrel(self, tmp_path: Path) -> None:
        util = tmp_path / "util.ts"
        barrel = tmp_path / "index.ts"
        server = tmp_path / "server.ts"
        util.write_text(
            """
export function helper(target: string): void {
  require("fs").unlinkSync(target);
}
""".strip()
            + "\n",
            encoding="utf-8",
        )
        barrel.write_text('export * from "./util";\n', encoding="utf-8")
        server.write_text(
            """
import { helper } from "./index";

export function handler(path: string): void {
  helper(path);
}
""".strip()
            + "\n",
            encoding="utf-8",
        )

        builder = CodeGraphBuilder()
        builder.add_path(util)
        builder.add_path(barrel)
        builder.add_path(server)
        built = builder.build()

        handler_id = next(nid for nid, n in built.nodes.items() if n.label == "handler")
        helper_id = next(nid for nid, n in built.nodes.items() if n.label == "helper")
        call_edges = [
            e
            for e in built.edges
            if e.source == handler_id
            and e.relation == Relation.CALLS
            and e.target == helper_id
        ]
        assert call_edges

    def test_directory_merged_graph_cache(self, tmp_path: Path) -> None:
        from mcpscanner.core.static_analysis.graph.cache import CodeGraphCache
        from mcpscanner.core.static_analysis.graph.integration import (
            build_code_graphs_for_registry,
        )

        util = tmp_path / "util.ts"
        server = tmp_path / "server.ts"
        util.write_text("export function helper(): void {}\n", encoding="utf-8")
        server.write_text(
            'import { helper } from "./util";\nexport function run(): void { helper(); }\n',
            encoding="utf-8",
        )
        registry = {str(util): util.read_text(), str(server): server.read_text()}
        cache_dir = tmp_path / "graph-cache"

        first = build_code_graphs_for_registry(registry)
        assert "typescript" in first

        cache = CodeGraphCache(cache_dir=cache_dir)
        cache.put_merged("typescript", registry, first["typescript"])
        second = cache.get_merged("typescript", registry)
        assert second is not None
        assert len(second.nodes) == len(first["typescript"].nodes)

    def test_java_registry_builds_graph(self, tmp_path: Path) -> None:
        from mcpscanner.core.static_analysis.graph.integration import (
            build_code_graphs_for_registry,
            language_for_path,
        )

        sample = tmp_path / "Server.java"
        sample.write_text(
            """
class Server {
  void helper(String target) {
    Runtime.getRuntime().exec(target);
  }

  void handler(String path) {
    helper(path);
  }
}
""".strip()
            + "\n",
            encoding="utf-8",
        )
        assert language_for_path(str(sample)) == "java"

        graphs = build_code_graphs_for_registry({str(sample): sample.read_text()})
        assert "java" in graphs
        built = graphs["java"]
        labels = {node.label for node in built.nodes.values()}
        assert any(label.endswith("handler") for label in labels)
        assert any(label.endswith("helper") for label in labels)

    def test_ruby_registry_builds_graph(self, tmp_path: Path) -> None:
        from mcpscanner.core.static_analysis.graph.integration import (
            build_code_graphs_for_registry,
        )

        sample = tmp_path / "server.rb"
        sample.write_text(
            """
def helper(target)
  system(target)
end

def handler(path)
  helper(path)
end
""".strip()
            + "\n",
            encoding="utf-8",
        )
        graphs = build_code_graphs_for_registry({str(sample): sample.read_text()})
        assert "ruby" in graphs
        labels = {node.label for node in graphs["ruby"].nodes.values()}
        assert "handler" in labels
        assert "helper" in labels

    def test_java_cfg_fusion_maps_argument_to_callee_param(self, tmp_path: Path) -> None:
        sample = tmp_path / "Server.java"
        sample.write_text(
            """
class Server {
  void helper(String target) {
    Runtime.getRuntime().exec(target);
  }

  void handler(String path) {
    helper(path);
  }
}
""".strip()
            + "\n",
            encoding="utf-8",
        )
        builder = CodeGraphBuilder()
        builder.add_path(sample)
        built = builder.build()

        entry = next(
            nid for nid, n in built.nodes.items() if n.label.endswith("handler")
        )
        helper = next(
            nid for nid, n in built.nodes.items() if n.label.endswith("helper")
        )
        call_edge = next(
            e
            for e in built.edges
            if e.source == entry and e.target == helper and e.relation == Relation.CALLS
        )

        bindings = CFGFusionEngine(built).bindings_for_edge(call_edge, {"path"})
        assert bindings
        assert bindings[0].caller_taint == "path"
        assert bindings[0].callee_param == "target"
        assert bindings[0].provenance == Provenance.EXTRACTED

        taint = InterproceduralTaintAnalyzer(built).analyze_entry(entry)
        assert any(step.parameter == "target" for step in taint.flows)

    def test_classic_dataflow_alias_propagation(self, tmp_path: Path) -> None:
        sample = tmp_path / "server.py"
        sample.write_text(
            """
import os

def helper(target: str) -> None:
    os.remove(target)

def delete_file(path: str) -> None:
    alias = path
    helper(alias)
""".strip()
            + "\n",
            encoding="utf-8",
        )
        builder = CodeGraphBuilder()
        builder.add_path(sample)
        built = builder.build()

        entry = next(nid for nid, n in built.nodes.items() if n.label == "delete_file")
        helper = next(nid for nid, n in built.nodes.items() if n.label == "helper")
        call_edge = next(
            e for e in built.edges if e.source == entry and e.target == helper
        )

        classic = ClassicDataflowEngine(built)
        classic.enrich_graph()
        summary = classic.get_summary(entry)
        assert summary is not None
        assert "alias" in summary.parameter_influenced
        assert "path" in summary.parameter_influenced
        assert built.nodes[entry].metadata.get("classic_dataflow")

        bindings = CFGFusionEngine(built, classic=classic).bindings_for_edge(
            call_edge, {"path"}
        )
        assert bindings
        assert bindings[0].callee_param == "target"

        taint = InterproceduralTaintAnalyzer(built).analyze_entry(entry)
        assert any(step.parameter == "target" for step in taint.flows)

    def test_ts_classic_dataflow_alias_propagation(self, tmp_path: Path) -> None:
        sample = tmp_path / "server.ts"
        sample.write_text(
            """
function helper(target: string): void {
  require("fs").unlinkSync(target);
}

function handler(path: string): void {
  const alias = path;
  helper(alias);
}
""".strip()
            + "\n",
            encoding="utf-8",
        )
        builder = CodeGraphBuilder()
        builder.add_path(sample)
        built = builder.build()

        entry = next(nid for nid, n in built.nodes.items() if n.label == "handler")
        helper = next(nid for nid, n in built.nodes.items() if n.label == "helper")
        call_edge = next(
            e for e in built.edges if e.source == entry and e.target == helper
        )

        classic = ClassicDataflowEngine(built)
        classic.enrich_graph()
        summary = classic.get_summary(entry)
        assert summary is not None
        assert summary.engine == "treesitter_classic"
        assert "alias" in summary.parameter_influenced
        assert built.nodes[entry].metadata.get("classic_dataflow")

        bindings = CFGFusionEngine(built, classic=classic).bindings_for_edge(
            call_edge, {"path"}
        )
        assert bindings
        assert bindings[0].callee_param == "target"

        taint = InterproceduralTaintAnalyzer(built).analyze_entry(entry)
        assert any(step.parameter == "target" for step in taint.flows)

    def test_ts_classic_dataflow_dead_assignment_filtered(self, tmp_path: Path) -> None:
        sample = tmp_path / "server.ts"
        sample.write_text(
            """
function helper(target: string): void {
  require("fs").unlinkSync(target);
}

function handler(path: string): void {
  const alias = path;
  const dead = path;
  helper(alias);
}
""".strip()
            + "\n",
            encoding="utf-8",
        )
        builder = CodeGraphBuilder()
        builder.add_path(sample)
        built = builder.build()

        entry = next(nid for nid, n in built.nodes.items() if n.label == "handler")
        classic = ClassicDataflowEngine(built)
        summary = classic.get_summary(entry)
        assert summary is not None
        assert "dead" in summary.dead_variables
        assert "alias" not in summary.dead_variables

    def test_ts_classic_dataflow_parameter_expressions(self, tmp_path: Path) -> None:
        sample = tmp_path / "server.ts"
        sample.write_text(
            """
function helper(target: string): void {}

function handler(path: string): void {
  const joined = path + ".txt";
  helper(joined);
}
""".strip()
            + "\n",
            encoding="utf-8",
        )
        builder = CodeGraphBuilder()
        builder.add_path(sample)
        built = builder.build()

        entry = next(nid for nid, n in built.nodes.items() if n.label == "handler")
        summary = ClassicDataflowEngine(built).get_summary(entry)
        assert summary is not None
        assert any("path" in expr for expr in summary.parameter_expressions)

    def test_swift_excluded_from_graph_registry(self, tmp_path: Path) -> None:
        from mcpscanner.core.static_analysis.graph.integration import (
            build_code_graphs_for_registry,
            language_for_path,
        )

        sample = tmp_path / "App.swift"
        sample.write_text("func run() {}\n", encoding="utf-8")
        assert language_for_path(str(sample)) == "swift"
        assert build_code_graphs_for_registry({str(sample): sample.read_text()}) == {}


class TestTreeSitterClassicHelpers:
    def test_expr_uses_vars_matches_dollar_prefixed_identifiers(self) -> None:
        from mcpscanner.core.static_analysis.dataflow.treesitter_classic import (
            _expr_uses_vars,
        )

        assert _expr_uses_vars("$input + 1", {"$input"})
        assert not _expr_uses_vars("$input + 1", {"input"})
        assert not _expr_uses_vars("reinput", {"input"})
