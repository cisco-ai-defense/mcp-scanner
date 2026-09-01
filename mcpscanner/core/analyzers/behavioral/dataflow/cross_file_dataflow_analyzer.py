# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Cross-file parameter-flow enrichment for behavioral analysis."""

from __future__ import annotations

from typing import Any, Union

from ....static_analysis.context_extractor import FunctionContext
from ....static_analysis.interprocedural.call_graph_analyzer import CallGraphAnalyzer
from ....static_analysis.interprocedural.treesitter_call_graph import (
    TreeSitterCallGraphAnalyzer,
)
from .....utils.logging_config import get_logger

logger = get_logger(__name__)


def enrich_with_cross_file_context(
    func_context: FunctionContext,
    file_path: str,
    call_graph_analyzer: Union[CallGraphAnalyzer, TreeSitterCallGraphAnalyzer],
) -> None:
    """Populate cross-file reachability and parameter-flow metadata on a context."""
    try:
        full_func_name = f"{file_path}::{func_context.name}"

        reachable = call_graph_analyzer.get_reachable_functions(full_func_name)
        if reachable:
            func_context.reachable_functions = reachable

        if not func_context.parameters:
            return

        param_names = [p.get("name") for p in func_context.parameters if p.get("name")]
        if not param_names:
            return

        if isinstance(call_graph_analyzer, TreeSitterCallGraphAnalyzer):
            flow_info = call_graph_analyzer.analyze_cross_file_flows(
                full_func_name, param_names
            )
        else:
            flow_info = call_graph_analyzer.analyze_parameter_flow_across_files(
                full_func_name, param_names
            )

        if flow_info.get("cross_file_flows"):
            func_context.cross_file_calls = flow_info["cross_file_flows"]

        func_context.dataflow_summary = dict(func_context.dataflow_summary or {})
        func_context.dataflow_summary["cross_file_analysis"] = {
            "total_reachable": len(reachable),
            "files_involved": flow_info.get("total_files_involved", 0),
            "param_influenced_functions": len(
                flow_info.get("param_influenced_functions", [])
            ),
        }
    except Exception as exc:
        logger.warning(
            "cross_file_dataflow enrich_failed file=%s function=%s error=%s",
            file_path,
            func_context.name,
            exc,
        )


class CrossFileDataflowAnalyzer:
    """Object-oriented wrapper used by tests and future orchestration hooks."""

    def enrich(
        self,
        func_context: FunctionContext,
        file_path: str,
        call_graph_analyzer: Union[CallGraphAnalyzer, TreeSitterCallGraphAnalyzer],
    ) -> None:
        enrich_with_cross_file_context(func_context, file_path, call_graph_analyzer)

    def analyze_parameter_flow(
        self,
        entry_point: str,
        param_names: list[str],
        call_graph_analyzer: Union[CallGraphAnalyzer, TreeSitterCallGraphAnalyzer],
    ) -> dict[str, Any]:
        if isinstance(call_graph_analyzer, TreeSitterCallGraphAnalyzer):
            return call_graph_analyzer.analyze_cross_file_flows(entry_point, param_names)
        return call_graph_analyzer.analyze_parameter_flow_across_files(
            entry_point, param_names
        )


cross_file_dataflow_analyzer = CrossFileDataflowAnalyzer()
