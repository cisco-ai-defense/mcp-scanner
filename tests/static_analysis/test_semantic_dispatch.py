# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from mcpscanner.core.static_analysis.graph.semantic_dispatch import (
    SemanticDispatchEngine,
    TypeHierarchy,
    build_python_hierarchy,
)


def test_python_hierarchy_tracks_bases_and_methods() -> None:
    source = """
class Base:
    def run(self, target: str) -> None:
        pass

class Child(Base):
    def run(self, target: str) -> None:
        import os
        os.remove(target)
"""
    hierarchy = build_python_hierarchy(source)
    assert hierarchy.bases["Child"] == ["Base"]
    assert "run" in hierarchy.methods["Child"]
    assert hierarchy.all_subtypes("Base") == {"Child"}


def test_type_hierarchy_virtual_resolution() -> None:
    hierarchy = TypeHierarchy(
        bases={"Child": ["Base"]},
        methods={"Base": {"run"}, "Child": {"run"}},
    )
    assert hierarchy.resolve_virtual("Base", "run") == {"Base", "Child"}


def test_semantic_dispatch_const_prop_and_multi_target() -> None:
    source = """
class WorkerA:
    def run(self, target: str) -> None:
        pass

class WorkerB:
    def run(self, target: str) -> None:
        pass

def handler(path: str, pick_a: bool) -> None:
    worker = WorkerA() if pick_a else WorkerB()
    method = "run"
    getattr(worker, method)(path)
"""
    known = {
        "/tmp/a.py::WorkerA.run",
        "/tmp/a.py::WorkerB.run",
        "/tmp/a.py::handler",
    }
    engine = SemanticDispatchEngine.for_file(
        language="python",
        source=source,
        known_functions=known,
        caller_file="/tmp/a.py",
        semantic=None,
    )
    result = engine.resolve(
        caller_label="handler",
        callee_label='getattr(worker, method)',
        receiver="worker",
        method=None,
        kind="getattr_variable",
    )
    assert len(result.targets) == 2
    assert result.provenance.value in {"inferred", "ambiguous"}
