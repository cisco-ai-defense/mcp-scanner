# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Integration tests for CodeGraph → BehavioralCodeAnalyzer bridge."""

from __future__ import annotations

from pathlib import Path

import pytest

from mcpscanner.config.constants import MCPScannerConstants
from mcpscanner.core.static_analysis.context_extractor import ContextExtractor, FunctionContext
from mcpscanner.core.static_analysis.graph.integration import (
    build_code_graph,
    is_actionable_sink_hit,
    partition_functions_by_graph,
)
from mcpscanner.core.static_analysis.interprocedural.call_graph_analyzer import (
    CallGraphAnalyzer,
)


def _tool_function_context(name: str, *, line_number: int = 1) -> FunctionContext:
    return FunctionContext(
        name=name,
        decorator_types=["tool"],
        imports=[],
        function_calls=[],
        assignments=[],
        control_flow={},
        parameter_flows=[],
        constants={},
        variable_dependencies={},
        has_file_operations=True,
        has_network_operations=False,
        has_subprocess_calls=False,
        has_eval_exec=False,
        has_dangerous_imports=False,
        line_number=line_number,
    )


FIXTURE = (
    Path(__file__).resolve().parents[2]
    / "evals/behavioral-analysis/data/arbitrary-resource-read-write"
    / "arbitrary_file_deletion_recursive.py"
)


def test_code_graph_enabled_by_default(monkeypatch):
    monkeypatch.delenv("MCP_SCANNER_CODE_GRAPH", raising=False)
    assert MCPScannerConstants.CODE_GRAPH_ENABLED is True


@pytest.mark.skipif(not FIXTURE.is_file(), reason="behavioral fixture missing")
class TestGraphBehavioralIntegration:
    def test_partition_enriches_file_deletion_for_llm(self) -> None:
        source = FIXTURE.read_text(encoding="utf-8")
        file_path = str(FIXTURE.resolve())

        cga = CallGraphAnalyzer()
        cga.add_file(file_path, source)
        graph = build_code_graph(cga, language="python")

        extractor = ContextExtractor(source, file_path)
        func_contexts = extractor.extract_mcp_function_contexts()
        delete_ctx = next(fc for fc in func_contexts if fc.name == "delete_file")

        findings, needs_llm = partition_functions_by_graph(
            [delete_ctx],
            graph,
            file_path,
        )

        assert not findings, "graph must not short-circuit LLM with direct findings"
        assert needs_llm == [delete_ctx]
        assert delete_ctx.dataflow_summary.get("code_graph_evidence")
        assert delete_ctx.dataflow_summary.get("code_graph_sink_hints")

    def test_is_actionable_ignores_generic_file_label(self) -> None:
        from mcpscanner.core.static_analysis.graph.models import Provenance, SinkHit

        generic = SinkHit(
            entry_id="/tmp/x.py::delete_file",
            sink_id="external::file",
            sink_name="file",
            category="file",
            path=["/tmp/x.py::delete_file"],
            provenance=Provenance.EXTRACTED,
        )
        assert not is_actionable_sink_hit(generic)

        specific = SinkHit(
            entry_id="/tmp/x.py::delete_file",
            sink_id="external::os.remove",
            sink_name="os.remove",
            category="file",
            path=[
                "/tmp/x.py::delete_file",
                "/tmp/x.py::FileDeletor.delete_file",
                "external::os.remove",
            ],
            provenance=Provenance.EXTRACTED,
        )
        assert is_actionable_sink_hit(specific)

    def test_partition_enriches_factory_dynamic_dispatch_for_llm(
        self, tmp_path: Path
    ) -> None:
        sample = tmp_path / "server.py"
        sample.write_text(
            """
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")

class FileWorker:
    def run(self, target: str) -> None:
        import os
        os.remove(target)

def factory():
    return FileWorker()

def get_method():
    return "run"

@mcp.tool()
def delete_file(path: str) -> None:
    worker = factory()
    method = get_method()
    getattr(worker, method)(path)
""".strip()
            + "\n",
            encoding="utf-8",
        )
        file_path = str(sample.resolve())
        source = sample.read_text(encoding="utf-8")

        cga = CallGraphAnalyzer()
        cga.add_file(file_path, source)
        graph = build_code_graph(cga, language="python", source_registry={file_path: source})

        extractor = ContextExtractor(source, file_path)
        delete_ctx = next(fc for fc in extractor.extract_mcp_function_contexts())

        findings, needs_llm = partition_functions_by_graph(
            [delete_ctx],
            graph,
            file_path,
        )

        assert not findings
        assert needs_llm == [delete_ctx]
        hints = delete_ctx.dataflow_summary.get("code_graph_sink_hints") or []
        assert hints
        assert "os.remove" in hints[0].get("sink_name", "")

    def test_partition_enriches_multifile_factory_dispatch_for_llm(
        self, tmp_path: Path
    ) -> None:
        from mcpscanner.core.static_analysis.graph.integration import (
            build_code_graphs_for_registry,
        )

        workers = tmp_path / "workers.py"
        server = tmp_path / "server.py"
        workers.write_text(
            """
class FileWorker:
    def run(self, target: str) -> None:
        import os
        os.remove(target)
""".strip()
            + "\n",
            encoding="utf-8",
        )
        server.write_text(
            """
from mcp.server.fastmcp import FastMCP
from workers import FileWorker

mcp = FastMCP("demo")

def factory():
    return FileWorker()

def get_method():
    return "run"

@mcp.tool()
def delete_file(path: str) -> None:
    worker = factory()
    method = get_method()
    getattr(worker, method)(path)
""".strip()
            + "\n",
            encoding="utf-8",
        )
        workers_path = str(workers.resolve())
        server_path = str(server.resolve())
        registry = {
            workers_path: workers.read_text(encoding="utf-8"),
            server_path: server.read_text(encoding="utf-8"),
        }

        graphs = build_code_graphs_for_registry(registry)
        graph = graphs["python"]

        extractor = ContextExtractor(server.read_text(encoding="utf-8"), server_path)
        delete_ctx = next(fc for fc in extractor.extract_mcp_function_contexts())

        findings, needs_llm = partition_functions_by_graph(
            [delete_ctx],
            graph,
            server_path,
        )

        assert not findings
        assert needs_llm == [delete_ctx]
        hints = delete_ctx.dataflow_summary.get("code_graph_sink_hints") or []
        assert hints
        assert "os.remove" in hints[0].get("sink_name", "")

    @pytest.mark.parametrize(
        ("language", "extension", "worker_source", "server_source", "sink_name"),
        [
            (
                "ruby",
                ".rb",
                """
class FileWorker
  def run(target)
    File.delete(target)
  end
end
""",
                """
def factory
  FileWorker.new
end

def get_method
  "run"
end

def delete_file(path)
  worker = factory()
  method = get_method()
  worker.send(method, path)
end
""",
                "file.delete",
            ),
            (
                "php",
                ".php",
                """<?php
class FileWorker {
    public function run($target) {
        unlink($target);
    }
}
""",
                """<?php
function factory() {
    return new FileWorker();
}

function getMethod() {
    return "run";
}

function delete_file($path) {
    $worker = factory();
    $method = getMethod();
    $worker->$method($path);
}
""",
                "unlink",
            ),
        ],
    )
    def test_partition_enriches_treesitter_factory_dispatch_for_llm(
        self,
        tmp_path: Path,
        language: str,
        extension: str,
        worker_source: str,
        server_source: str,
        sink_name: str,
    ) -> None:
        from mcpscanner.core.static_analysis.graph.integration import (
            build_code_graphs_for_registry,
        )

        workers = tmp_path / f"workers{extension}"
        server = tmp_path / f"server{extension}"
        workers.write_text(worker_source.strip() + "\n", encoding="utf-8")
        server.write_text(server_source.strip() + "\n", encoding="utf-8")
        workers_path = str(workers.resolve())
        server_path = str(server.resolve())
        registry = {
            workers_path: workers.read_text(encoding="utf-8"),
            server_path: server.read_text(encoding="utf-8"),
        }

        graph = build_code_graphs_for_registry(registry)[language]
        delete_ctx = _tool_function_context("delete_file")

        findings, needs_llm = partition_functions_by_graph(
            [delete_ctx],
            graph,
            server_path,
        )

        assert not findings
        assert needs_llm == [delete_ctx]
        hints = delete_ctx.dataflow_summary.get("code_graph_sink_hints") or []
        assert hints
        assert sink_name in hints[0].get("sink_name", "")

    def test_partition_enriches_typescript_multifile_factory_for_llm(
        self, tmp_path: Path
    ) -> None:
        from mcpscanner.core.static_analysis.graph.integration import (
            build_code_graphs_for_registry,
        )

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

export function delete_file(path: string): void {
  const worker = factory();
  const method = getMethod();
  (worker as any)[method](path);
}
""".strip()
            + "\n",
            encoding="utf-8",
        )
        workers_path = str(workers.resolve())
        server_path = str(server.resolve())
        registry = {
            workers_path: workers.read_text(encoding="utf-8"),
            server_path: server.read_text(encoding="utf-8"),
        }

        graph = build_code_graphs_for_registry(registry)["typescript"]
        delete_ctx = _tool_function_context("delete_file")

        findings, needs_llm = partition_functions_by_graph(
            [delete_ctx],
            graph,
            server_path,
        )

        assert not findings
        assert needs_llm == [delete_ctx]
        hints = delete_ctx.dataflow_summary.get("code_graph_sink_hints") or []
        assert hints
        assert "unlink" in hints[0].get("sink_name", "").lower()

    def test_resolve_entry_id_normalizes_private_var(self, tmp_path: Path) -> None:
        from mcpscanner.core.static_analysis.graph.integration import resolve_entry_id
        from mcpscanner.core.static_analysis.graph.models import CodeGraph, CodeNode

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

        alt = f"/private{resolved}" if str(resolved).startswith("/var/") else str(resolved)
        assert resolve_entry_id(graph, alt, "tool_alpha") == node_id

        cases = [
            (
                "symlink_attack_file_access_bypass.py",
                "create_link",
            ),
            (
                "file_permission_manipulation_privilege_escalation.py",
                "change_permissions",
            ),
        ]
        for filename, func_name in cases:
            fixture = FIXTURE.parent / filename
            if not fixture.is_file():
                pytest.skip(f"missing {filename}")
            source = fixture.read_text(encoding="utf-8")
            file_path = str(fixture.resolve())
            cga = CallGraphAnalyzer()
            cga.add_file(file_path, source)
            graph = build_code_graph(cga, language="python")
            extractor = ContextExtractor(source, file_path)
            func_contexts = extractor.extract_mcp_function_contexts()
            target = next(fc for fc in func_contexts if fc.name == func_name)
            findings, needs_llm = partition_functions_by_graph(
                [target],
                graph,
                file_path,
            )
            assert not findings
            assert needs_llm == [target]
            assert target.dataflow_summary.get("code_graph_evidence")
