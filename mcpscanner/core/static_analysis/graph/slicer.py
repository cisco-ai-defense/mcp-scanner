# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Bounded subgraph extraction from an MCP entry point."""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import CodeGraph, CodeEdge, Relation


@dataclass
class GraphSlice:
    """A bounded subgraph around one MCP entry point."""

    entry_id: str
    node_ids: set[str] = field(default_factory=set)
    edges: list[CodeEdge] = field(default_factory=list)
    hop_limit: int = 0

    @property
    def size(self) -> int:
        return len(self.node_ids)


class GraphSlicer:
    """Extract call-bounded evidence slices for LLM prompts."""

    def __init__(self, graph: CodeGraph) -> None:
        self._graph = graph

    def slice(
        self,
        entry_id: str,
        *,
        max_hops: int = 6,
        max_nodes: int = 40,
        max_chars: int | None = 8000,
    ) -> GraphSlice:
        if entry_id not in self._graph.nodes:
            return GraphSlice(entry_id=entry_id)

        node_ids: set[str] = {entry_id}
        edges: list[CodeEdge] = []
        frontier = [entry_id]
        hops = 0

        while frontier and hops < max_hops and len(node_ids) < max_nodes:
            next_frontier: list[str] = []
            for node_id in frontier:
                for edge in self._graph.edges:
                    if edge.source != node_id or edge.relation != Relation.CALLS:
                        continue
                    if edge.target in node_ids:
                        edges.append(edge)
                        continue
                    if len(node_ids) >= max_nodes:
                        break
                    node_ids.add(edge.target)
                    edges.append(edge)
                    next_frontier.append(edge.target)
            frontier = next_frontier
            hops += 1

        trimmed = self._trim_nodes(node_ids, max_chars)
        trimmed_edges = [
            edge
            for edge in edges
            if edge.source in trimmed and edge.target in trimmed
        ]
        return GraphSlice(
            entry_id=entry_id,
            node_ids=trimmed,
            edges=trimmed_edges,
            hop_limit=hops,
        )

    def _trim_nodes(self, node_ids: set[str], max_chars: int | None) -> set[str]:
        if max_chars is None:
            return node_ids
        kept: set[str] = set()
        budget = max_chars
        for node_id in sorted(node_ids):
            label_len = len(node_id)
            if budget - label_len < 0 and kept:
                break
            kept.add(node_id)
            budget -= label_len
        return kept or node_ids
