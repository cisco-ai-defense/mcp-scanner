# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Populate structured taint fields on FunctionContext from dataflow evidence."""

from __future__ import annotations

from typing import Any

from ..context_extractor import FunctionContext
from .sink_analyzer import _match_sink, _sink_lookup


def _language_for_context(func_context: FunctionContext) -> str:
    summary = func_context.dataflow_summary or {}
    language = summary.get("language") or summary.get("code_graph_language")
    if isinstance(language, str) and language.strip():
        return language.strip().lower()
    return "python"


def _is_sink_call(callee: str, language: str) -> bool:
    sinks = _sink_lookup(language)
    return _match_sink(callee, sinks) is not None


def populate_taint_fields(func_context: FunctionContext) -> None:
    """
    Derive structured taint sources, sinks, and flows from the function context's parameter and dataflow information.
    
    Parameters:
    	func_context (FunctionContext): Function context to update with the derived taint metadata.
    """
    sources: list[dict[str, Any]] = []
    sinks: list[dict[str, Any]] = []
    flows: list[dict[str, Any]] = []
    language = _language_for_context(func_context)

    for flow in func_context.parameter_flows or []:
        param = flow.get("parameter", "unknown")
        sources.append(
            {
                "name": param,
                "kind": "mcp_parameter",
                "provenance": "extracted",
                "confidence": 1.0,
            }
        )

        for op in flow.get("operations") or []:
            op_type = op.get("type", "unknown")
            line = op.get("line", 0)
            if op_type != "function_call":
                continue
            callee = op.get("function", "?")
            if not _is_sink_call(callee, language):
                flows.append(
                    {
                        "source": param,
                        "sink": callee,
                        "line": line,
                        "steps": [param, callee],
                        "provenance": "inferred",
                        "confidence": 0.5,
                    }
                )
                continue
            entry = {
                "sink": callee,
                "line": line,
                "parameter": param,
                "provenance": "extracted",
                "confidence": 1.0,
            }
            sinks.append(entry)
            flows.append(
                {
                    "source": param,
                    "sink": callee,
                    "line": line,
                    "steps": [param, callee],
                    "provenance": "extracted",
                    "confidence": 1.0,
                }
            )

        if flow.get("reaches_external"):
            flows.append(
                {
                    "source": param,
                    "sink": "external_operation",
                    "line": 0,
                    "steps": [param, "external"],
                    "provenance": "inferred",
                    "confidence": 0.75,
                }
            )

    graph_flows = (func_context.dataflow_summary or {}).get("taint_flows") or []
    for item in graph_flows:
        if isinstance(item, dict):
            flows.append(item)

    func_context.taint_sources = sources
    func_context.taint_sinks = sinks
    func_context.taint_flows = flows
