# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Cross-function fixpoint call-graph refinement across graph-supported languages."""

from __future__ import annotations

from pathlib import Path

import pytest

from mcpscanner.core.static_analysis.graph import (
    CodeGraphBuilder,
    InterproceduralTaintAnalyzer,
    Relation,
    SinkAnalyzer,
)
from mcpscanner.core.static_analysis.graph.builder import GRAPH_SUPPORTED_LANGUAGES
from mcpscanner.core.static_analysis.graph.fixpoint import call_edges_without_superseded_external
from mcpscanner.core.static_analysis.graph.models import CodeEdge, Provenance
from mcpscanner.core.static_analysis.native_analyzer import NativeAnalyzer

_CROSS_FUNCTION_SNIPPETS: dict[str, str] = {
    "python": """
class FileWorker:
    def run(self, target: str) -> None:
        import os
        os.remove(target)

def factory():
    return FileWorker()

def get_method():
    return "run"

def handler(path: str) -> None:
    worker = factory()
    method = get_method()
    getattr(worker, method)(path)
""",
    "typescript": """
class FileWorker {
  run(target: string): void {
    require("fs").unlinkSync(target);
  }
}

function factory(): FileWorker {
  return new FileWorker();
}

function getMethod(): string {
  return "run";
}

export function handler(path: string): void {
  const worker = factory();
  const method = getMethod();
  worker[method](path);
}
""",
    "javascript": """
class FileWorker {
  run(target) {
    require("fs").unlinkSync(target);
  }
}

function factory() {
  return new FileWorker();
}

function getMethod() {
  return "run";
}

function handler(path) {
  const worker = factory();
  const method = getMethod();
  worker[method](path);
}
""",
    "java": """
class FileWorker {
    void run(String target) {}
}

class App {
    FileWorker factory() {
        return new FileWorker();
    }

    void handler(String path) {
        FileWorker worker = factory();
        worker.run(path);
    }
}
""",
    "kotlin": """
class FileWorker {
    fun run(target: String) {}
}

class App {
    fun factory(): FileWorker = FileWorker()

    fun handler(path: String) {
        val worker = factory()
        worker.run(path)
    }
}
""",
    "c_sharp": """
class FileWorker {
    public void Run(string target) {}
}

class App {
    FileWorker Factory() => new FileWorker();

    void Handler(string path) {
        var worker = Factory();
        worker.Run(path);
    }
}
""",
    "go": """
package main

type FileWorker struct{}

func (f FileWorker) Run(target string) {}

func factory() FileWorker {
    return FileWorker{}
}

func handler(path string) {
    worker := factory()
    worker.Run(path)
}
""",
    "rust": """
struct FileWorker;

impl FileWorker {
    fn run(&self, target: &str) {}
}

fn factory() -> FileWorker {
    FileWorker
}

fn handler(path: &str) {
    let worker = factory();
    worker.run(path);
}
""",
    "ruby": """
class FileWorker
  def run(target)
  end
end

def factory
  FileWorker.new
end

def get_method
  "run"
end

def handler(path)
  worker = factory()
  method = get_method()
  worker.send(method, path)
end
""",
    "php": """
<?php
class FileWorker {
    public function run($target) {}
}

function factory() {
    return new FileWorker();
}

function getMethod() {
    return "run";
}

function handler($path) {
    $worker = factory();
    $method = getMethod();
    $worker->$method($path);
}
""",
}

_EXT_FOR_LANG = {
    "python": ".py",
    "typescript": ".ts",
    "javascript": ".js",
    "java": ".java",
    "kotlin": ".kt",
    "c_sharp": ".cs",
    "go": ".go",
    "rust": ".rs",
    "ruby": ".rb",
    "php": ".php",
}

_RUN_SUFFIXES = (".run", ".Run", "::run", "::Run")


def test_call_edges_without_superseded_external() -> None:
    resolved = CodeEdge(
        source="a::handler",
        target="a::FileWorker.run",
        relation=Relation.CALLS,
        provenance=Provenance.EXTRACTED,
        call_expression="getattr(worker, method)",
    )
    external = CodeEdge(
        source="a::handler",
        target="external::getattr",
        relation=Relation.CALLS,
        provenance=Provenance.AMBIGUOUS,
        call_expression="getattr",
    )
    kept = call_edges_without_superseded_external([resolved, external])
    assert kept == [resolved]


def _handler_node_id(nodes: dict) -> str:
    for node_id, node in nodes.items():
        label = node.label.split(".")[-1]
        if label in {"handler", "Handler"}:
            return node_id
    raise AssertionError("handler node not found")


def _assert_handler_resolves_run(graph) -> None:
    handler_id = _handler_node_id(graph.nodes)
    call_edges = [
        e
        for e in graph.edges
        if e.source == handler_id
        and e.relation == Relation.CALLS
        and not e.target.startswith("external::")
    ]
    assert call_edges, (
        f"no resolved call edges from {handler_id}; "
        f"targets={[e.target for e in graph.edges if e.source == handler_id]}"
    )
    assert any(
        any(suffix in e.target for suffix in _RUN_SUFFIXES)
        or e.target.split("::")[-1].lower().endswith("run")
        for e in call_edges
    ), call_edges


@pytest.mark.parametrize("language", sorted(GRAPH_SUPPORTED_LANGUAGES))
def test_fixpoint_cross_function_factory_dispatch(
    tmp_path: Path, language: str
) -> None:
    snippet = _CROSS_FUNCTION_SNIPPETS.get(language)
    assert snippet is not None, f"missing snippet for {language}"
    ext = _EXT_FOR_LANG[language]
    assert ext in NativeAnalyzer.EXTENSION_MAP
    sample = tmp_path / f"server{ext}"
    sample.write_text(snippet.strip() + "\n", encoding="utf-8")

    builder = CodeGraphBuilder()
    builder.add_path(sample)
    graph = builder.build()

    _assert_handler_resolves_run(graph)


def test_fixpoint_cross_function_taint_reaches_sink(tmp_path: Path) -> None:
    """Fixpoint-resolved dispatch should carry taint through factory to os.remove."""
    sample = tmp_path / "server.py"
    sample.write_text(
        """
class FileWorker:
    def run(self, target: str) -> None:
        import os
        os.remove(target)

def factory():
    return FileWorker()

def get_method():
    return "run"

def handler(path: str) -> None:
    worker = factory()
    method = get_method()
    getattr(worker, method)(path)
""".strip()
        + "\n",
        encoding="utf-8",
    )

    builder = CodeGraphBuilder()
    builder.add_path(sample)
    graph = builder.build()
    handler_id = _handler_node_id(graph.nodes)
    graph.entry_points.add(handler_id)

    handler_calls = [
        e
        for e in graph.edges
        if e.source == handler_id and e.relation == Relation.CALLS
    ]
    assert not any(e.target.startswith("external::getattr") for e in handler_calls)
    assert any("FileWorker.run" in e.target for e in handler_calls)

    taint = InterproceduralTaintAnalyzer(graph).analyze_entry(handler_id)
    assert any(step.target_id.endswith("::FileWorker.run") for step in taint.flows)
    assert any("os.remove" in step.target_id for step in taint.flows)
    assert not any(
        "external::getattr" in step.target_id for step in taint.flows
    )

    sinks = SinkAnalyzer(graph).analyze_entry(handler_id)
    assert any(hit.sink_name == "os.remove" for hit in sinks.hits)
