# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Populate structured taint fields on FunctionContext from dataflow evidence."""

from __future__ import annotations

from typing import Any

from ..context_extractor import FunctionContext


def populate_taint_fields(func_context: FunctionContext) -> None:
    """
    Derive structured taint sources, sinks, and flows from the function context's parameter and dataflow information.
    
    Parameters:
    	func_context (FunctionContext): Function context to update with the derived taint metadata.
    """
    sources: list[dict[str, Any]] = []
    sinks: list[dict[str, Any]] = []
    flows: list[dict[str, Any]] = []

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
            if op_type == "function_call":
                callee = op.get("function", "?")
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
