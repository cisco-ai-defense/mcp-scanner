# Copyright 2025 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Tests for CrossFileDataflowAnalyzer component"""

from pathlib import Path

from mcpscanner.core.analyzers.behavioral.dataflow import (
    CrossFileDataflowAnalyzer,
    cross_file_dataflow_analyzer,
    enrich_with_cross_file_context,
)
from mcpscanner.core.static_analysis.context_extractor import FunctionContext
from mcpscanner.core.static_analysis.interprocedural.call_graph_analyzer import (
    CallGraphAnalyzer,
)


def _minimal_context(name: str = "handler") -> FunctionContext:
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
        has_file_operations=False,
        has_network_operations=False,
        has_subprocess_calls=False,
        has_eval_exec=False,
        has_dangerous_imports=False,
        parameters=[{"name": "path"}],
    )


class TestCrossFileDataflowAnalyzer:
    def test_module_exports(self) -> None:
        assert cross_file_dataflow_analyzer is not None
        assert isinstance(cross_file_dataflow_analyzer, CrossFileDataflowAnalyzer)

    def test_enrich_is_callable(self) -> None:
        ctx = _minimal_context()
        enrich_with_cross_file_context(ctx, "/tmp/x.py", _FakeCallGraph())
        assert ctx.dataflow_summary.get("cross_file_analysis") is not None

    def test_enrich_matches_call_graph_when_scan_path_is_resolved(
        self, tmp_path, monkeypatch
    ) -> None:
        """The call graph is keyed by the path passed to ``add_file``.

        ``_analyze_file`` hands the enricher a resolved path, so lookup must
        still match when the two spellings differ.
        """
        sample = tmp_path / "server.py"
        sample.write_text(
            "def helper(path):\n"
            "    return path\n"
            "\n"
            "def handler(path):\n"
            "    return helper(path)\n",
            encoding="utf-8",
        )
        monkeypatch.chdir(tmp_path)
        analyzer = CallGraphAnalyzer()
        analyzer.add_file(Path("server.py"), sample.read_text(encoding="utf-8"))
        analyzer.build_call_graph()

        ctx = _minimal_context("handler")
        enrich_with_cross_file_context(ctx, str(sample.resolve()), analyzer)
        assert any(
            name.endswith("::helper") for name in (ctx.reachable_functions or [])
        )


class _FakeCallGraph:
    def get_reachable_functions(self, _name: str):
        return ["/tmp/x.py::helper"]

    def analyze_parameter_flow_across_files(self, _entry: str, _params: list[str]):
        return {
            "cross_file_flows": [],
            "total_files_involved": 1,
            "param_influenced_functions": [],
        }
