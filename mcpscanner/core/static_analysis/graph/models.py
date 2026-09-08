# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Deterministic code graph models for behavioral security analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class Provenance(str, Enum):
    """How a graph fact was obtained."""

    EXTRACTED = "extracted"
    INFERRED = "inferred"
    AMBIGUOUS = "ambiguous"


class Relation(str, Enum):
    """Edge types in the security-oriented code graph."""

    CONTAINS = "contains"
    CALLS = "calls"
    IMPORTS = "imports"
    REACHES_SINK = "reaches_sink"
    TAINT_FLOW = "taint_flow"


GRAPH_IR_VERSION = "2"


@dataclass
class TaintFlowRecord:
    """Serializable interprocedural taint step stored on the graph."""

    source_id: str
    target_id: str
    parameter: str
    provenance: Provenance
    confidence: float = 1.0
    line: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "parameter": self.parameter,
            "provenance": self.provenance.value,
            "confidence": self.confidence,
            "line": self.line,
        }


@dataclass
class CodeNode:
    """A function, module, or sink symbol in the code graph."""

    node_id: str
    label: str
    source_file: str
    language: str
    kind: str = "function"
    line: int | None = None
    is_mcp_entry: bool = False
    module_id: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.module_id and self.source_file:
            self.module_id = str(Path(self.source_file).resolve())

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "label": self.label,
            "source_file": self.source_file,
            "language": self.language,
            "kind": self.kind,
            "line": self.line,
            "is_mcp_entry": self.is_mcp_entry,
            "module_id": self.module_id,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CodeNode:
        return cls(
            node_id=data["node_id"],
            label=data["label"],
            source_file=data.get("source_file", ""),
            language=data.get("language", "python"),
            kind=data.get("kind", "function"),
            line=data.get("line"),
            is_mcp_entry=bool(data.get("is_mcp_entry")),
            module_id=data.get("module_id", ""),
            metadata=dict(data.get("metadata") or {}),
        )

    @property
    def short_name(self) -> str:
        if "::" in self.node_id:
            return self.node_id.split("::", 1)[1]
        return self.label


@dataclass
class CodeEdge:
    """A directed relationship between two code nodes."""

    source: str
    target: str
    relation: Relation
    provenance: Provenance
    line: int | None = None
    confidence_score: float = 1.0
    context: str | None = None
    call_expression: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "relation": self.relation.value,
            "provenance": self.provenance.value,
            "line": self.line,
            "confidence_score": self.confidence_score,
            "context": self.context,
            "call_expression": self.call_expression,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CodeEdge:
        return cls(
            source=data["source"],
            target=data["target"],
            relation=Relation(data["relation"]),
            provenance=Provenance(data["provenance"]),
            line=data.get("line"),
            confidence_score=float(data.get("confidence_score", 1.0)),
            context=data.get("context"),
            call_expression=data.get("call_expression"),
        )


@dataclass
class SinkHit:
    """A deterministic sink reached from an MCP entry point."""

    entry_id: str
    sink_id: str
    category: str
    sink_name: str
    provenance: Provenance
    path: list[str] = field(default_factory=list)

    @property
    def definitive(self) -> bool:
        return self.provenance == Provenance.EXTRACTED


@dataclass
class CodeGraph:
    """In-memory security code graph for one scan target."""

    nodes: dict[str, CodeNode] = field(default_factory=dict)
    edges: list[CodeEdge] = field(default_factory=list)
    entry_points: set[str] = field(default_factory=set)
    language: str | None = None
    source_registry: dict[str, str] = field(default_factory=dict)
    taint_flows: list[TaintFlowRecord] = field(default_factory=list)
    version: str = GRAPH_IR_VERSION

    def add_node(self, node: CodeNode) -> None:
        self.nodes[node.node_id] = node
        if node.is_mcp_entry:
            self.entry_points.add(node.node_id)

    def add_edge(self, edge: CodeEdge) -> None:
        self.edges.append(edge)

    def neighbors(
        self,
        node_id: str,
        *,
        relation: Relation | None = Relation.CALLS,
    ) -> list[str]:
        out: list[str] = []
        for edge in self.edges:
            if edge.source != node_id:
                continue
            if relation is not None and edge.relation != relation:
                continue
            out.append(edge.target)
        return out

    def get_callees(self, node_id: str) -> list[str]:
        return self.neighbors(node_id, relation=Relation.CALLS)

    def reachable(
        self,
        start: str,
        *,
        max_hops: int | None = None,
    ) -> list[str]:
        """BFS reachability over call edges."""
        if start not in self.nodes:
            return []

        visited: list[str] = []
        seen = {start}
        frontier = [start]
        hops = 0

        while frontier and (max_hops is None or hops < max_hops):
            next_frontier: list[str] = []
            for node_id in frontier:
                for callee in self.get_callees(node_id):
                    if callee in seen:
                        continue
                    seen.add(callee)
                    visited.append(callee)
                    next_frontier.append(callee)
            frontier = next_frontier
            hops += 1

        return visited

    def edge_between(
        self,
        source: str,
        target: str,
        *,
        relation: Relation | None = None,
    ) -> CodeEdge | None:
        for edge in self.edges:
            if edge.source != source or edge.target != target:
                continue
            if relation is not None and edge.relation != relation:
                continue
            return edge
        return None

    def stats(self) -> dict[str, int]:
        return {
            "nodes": len(self.nodes),
            "edges": len(self.edges),
            "entry_points": len(self.entry_points),
            "calls": sum(1 for e in self.edges if e.relation == Relation.CALLS),
            "taint_flows": sum(1 for e in self.edges if e.relation == Relation.TAINT_FLOW),
            "reaches_sink": sum(
                1 for e in self.edges if e.relation == Relation.REACHES_SINK
            ),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "language": self.language,
            "nodes": {nid: node.to_dict() for nid, node in self.nodes.items()},
            "edges": [edge.to_dict() for edge in self.edges],
            "entry_points": sorted(self.entry_points),
            "taint_flows": [flow.to_dict() for flow in self.taint_flows],
            "source_registry": self.source_registry,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CodeGraph:
        graph = cls(
            language=data.get("language"),
            version=data.get("version", GRAPH_IR_VERSION),
        )
        for node_data in data.get("nodes", {}).values():
            graph.add_node(CodeNode.from_dict(node_data))
        for edge_data in data.get("edges", []):
            graph.add_edge(CodeEdge.from_dict(edge_data))
        for entry in data.get("entry_points", []):
            graph.entry_points.add(entry)
        for flow_data in data.get("taint_flows", []):
            graph.taint_flows.append(
                TaintFlowRecord(
                    source_id=flow_data["source_id"],
                    target_id=flow_data["target_id"],
                    parameter=flow_data["parameter"],
                    provenance=Provenance(flow_data["provenance"]),
                    confidence=float(flow_data.get("confidence", 1.0)),
                    line=flow_data.get("line"),
                )
            )
        registry = data.get("source_registry")
        if isinstance(registry, dict):
            graph.source_registry = {str(k): str(v) for k, v in registry.items()}
        return graph
