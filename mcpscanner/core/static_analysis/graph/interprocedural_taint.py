# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Interprocedural taint propagation over CodeGraph call edges."""

from __future__ import annotations

from dataclasses import dataclass, field

from .cfg_fusion import CFGFusionEngine, ParamBinding
from .fixpoint import call_edges_without_superseded_external
from .models import CodeGraph, CodeEdge, Provenance, Relation


@dataclass
class TaintFlowStep:
    """One hop in an interprocedural taint path."""

    source_id: str
    target_id: str
    parameter: str
    provenance: Provenance
    confidence: float = 1.0
    line: int | None = None
    caller_taint: str | None = None


@dataclass
class InterproceduralTaintResult:
    entry_id: str
    flows: list[TaintFlowStep] = field(default_factory=list)
    sink_reachability: list[str] = field(default_factory=list)

    def to_dicts(self) -> list[dict]:
        return [
            {
                "source": step.source_id,
                "sink": step.target_id,
                "parameter": step.parameter,
                "caller_taint": step.caller_taint,
                "provenance": step.provenance.value,
                "confidence": step.confidence,
                "line": step.line,
            }
            for step in self.flows
        ]


class InterproceduralTaintAnalyzer:
    """Propagate MCP-parameter taint across resolved call-graph edges."""

    def __init__(
        self,
        graph: CodeGraph,
        *,
        fusion: CFGFusionEngine | None = None,
    ) -> None:
        self._graph = graph
        from .classic_dataflow import ClassicDataflowEngine

        self._classic = ClassicDataflowEngine(graph)
        self._classic.enrich_graph()
        self._fusion = fusion or CFGFusionEngine(graph, classic=self._classic)

    def analyze_entry(self, entry_id: str) -> InterproceduralTaintResult:
        result = InterproceduralTaintResult(entry_id=entry_id)
        if entry_id not in self._graph.nodes:
            return result

        entry_node = self._graph.nodes[entry_id]
        tainted_params = {
            p.get("name", f"param_{idx}")
            for idx, p in enumerate(entry_node.metadata.get("parameters", []))
        }
        if not tainted_params:
            tainted_params = {"__mcp_input__"}

        queue: list[tuple[str, str]] = [(entry_id, param) for param in tainted_params]
        seen: set[tuple[str, str]] = set(queue)

        while queue:
            node_id, param = queue.pop(0)
            active = {param}
            for edge in self._callees(node_id):
                bindings = self._fusion.bindings_for_edge(edge, active)
                if not bindings:
                    bindings = self._fallback_bindings(edge, param)

                for binding in bindings:
                    step = TaintFlowStep(
                        source_id=node_id,
                        target_id=edge.target,
                        parameter=binding.callee_param,
                        provenance=binding.provenance,
                        confidence=binding.confidence,
                        line=binding.line or edge.line,
                        caller_taint=binding.caller_taint,
                    )
                    result.flows.append(step)
                    self._graph.add_edge(
                        CodeEdge(
                            source=node_id,
                            target=edge.target,
                            relation=Relation.TAINT_FLOW,
                            provenance=binding.provenance,
                            confidence_score=binding.confidence,
                            line=step.line,
                            context=f"{binding.caller_taint}->{binding.callee_param}",
                        )
                    )
                    key = (edge.target, binding.callee_param)
                    if key not in seen:
                        seen.add(key)
                        queue.append(key)

                    if edge.target.startswith("external::"):
                        result.sink_reachability.append(edge.target)

        return result

    def _fallback_bindings(self, edge: CodeEdge, param: str) -> list[ParamBinding]:
        callee = self._graph.nodes.get(edge.target)
        if callee is None:
            return [
                ParamBinding(
                    caller_taint=param,
                    callee_param=param,
                    provenance=edge.provenance,
                    confidence=edge.confidence_score,
                    line=edge.line,
                )
            ]

        callee_params = [p["name"] for p in callee.metadata.get("parameters", [])]
        if param in callee_params:
            return [
                ParamBinding(
                    caller_taint=param,
                    callee_param=param,
                    provenance=edge.provenance,
                    confidence=edge.confidence_score,
                    line=edge.line,
                )
            ]
        if callee_params:
            return [
                ParamBinding(
                    caller_taint=param,
                    callee_param=callee_params[0],
                    provenance=Provenance.INFERRED,
                    confidence=min(edge.confidence_score, 0.65),
                    line=edge.line,
                )
            ]
        return [
            ParamBinding(
                caller_taint=param,
                callee_param=param,
                provenance=edge.provenance,
                confidence=edge.confidence_score,
                line=edge.line,
            )
        ]

    def _callees(self, node_id: str) -> list[CodeEdge]:
        edges = [
            edge
            for edge in self._graph.edges
            if edge.source == node_id and edge.relation == Relation.CALLS
        ]
        return call_edges_without_superseded_external(edges)
