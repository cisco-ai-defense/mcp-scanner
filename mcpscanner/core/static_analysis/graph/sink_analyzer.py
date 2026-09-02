# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Deterministic sink detection over a CodeGraph."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..taint.patterns import get_all_sinks_for_language
from .interprocedural_taint import InterproceduralTaintAnalyzer
from .models import CodeGraph, Provenance, Relation, SinkHit


def _normalize_lang(language: str | None) -> str:
    """
    Normalize a language identifier for sink-catalog lookup.
    
    Parameters:
    	language (str | None): The language identifier to normalize.
    
    Returns:
    	str: The normalized language identifier, defaulting to `"python"` when none is provided.
    """
    if not language:
        return "python"
    lang = language.lower()
    if lang in ("typescript", "tsx"):
        return "javascript"
    if lang == "c_sharp":
        return "csharp"
    return lang


def _sink_lookup(language: str | None) -> dict[str, set[str]]:
    """Build a case-insensitive sink catalog for the specified language.
    
    Parameters:
    	language (str | None): Language whose sink catalog should be loaded.
    
    Returns:
    	dict[str, set[str]]: Sink categories mapped to lowercased sink names.
    """
    sinks = get_all_sinks_for_language(_normalize_lang(language))
    flat: dict[str, set[str]] = {}
    for category, names in sinks.items():
        flat[category] = {n.lower() for n in names}
    return flat


_REQUIRE_FS_RE = re.compile(r"""require\(\s*['"]fs['"]\s*\)\.(\w+)""", re.IGNORECASE)


def _normalize_sink_label(label: str) -> str:
    """Map chained ``require('fs').unlinkSync`` labels to catalog names."""
    match = _REQUIRE_FS_RE.search(label)
    if match:
        return f"fs.{match.group(1)}"
    return label


def _match_sink(label: str, sinks: dict[str, set[str]]) -> tuple[str, str] | None:
    """Find the sink category and name matching a label.
    
    Parameters:
    	label (str): Sink label to match.
    	sinks (dict[str, set[str]]): Sink catalog grouped by category.
    
    Returns:
    	tuple[str, str] | None: The matching category and sink name, or `None` when no match is found.
    """
    normalized = _normalize_sink_label(label)
    for candidate in (label, normalized):
        lower = candidate.lower()
        for category, names in sinks.items():
            for name in names:
                if lower == name or lower.endswith(f".{name}") or lower.endswith(f"::{name}"):
                    return category, name
    return None


@dataclass
class SinkAnalysisResult:
    """All sink hits from one entry point."""

    entry_id: str
    hits: list[SinkHit] = field(default_factory=list)
    taint_flows: list = field(default_factory=list)

    @property
    def has_definitive_hit(self) -> bool:
        """Determine whether any recorded sink hit is definitive.
        
        Returns:
        	bool: `true` if at least one hit is definitive, `false` otherwise.
        """
        return any(hit.definitive for hit in self.hits)

    @property
    def categories(self) -> set[str]:
        """Return the set of categories represented by the recorded sink hits.
        
        Returns:
            set[str]: The categories associated with the sink hits.
        """
        return {hit.category for hit in self.hits}


class SinkAnalyzer:
    """Walk call graph from MCP entries and match sink catalogs."""

    def __init__(self, graph: CodeGraph) -> None:
        """Initialize the analyzer with a code graph and its language-specific sink catalog.
        
        Parameters:
        	graph (CodeGraph): The code graph to analyze.
        """
        self._graph = graph
        self._sinks = _sink_lookup(graph.language)

    def analyze_entry(self, entry_id: str) -> SinkAnalysisResult:
        """
        Analyze an entry point for reachable sinks and record associated taint flows.
        
        Parameters:
        	entry_id (str): Identifier of the entry point to analyze.
        
        Returns:
        	SinkAnalysisResult: Detected sink hits and their call paths. An unknown entry point produces an empty result.
        """
        result = SinkAnalysisResult(entry_id=entry_id)
        if entry_id not in self._graph.nodes:
            return result

        taint = InterproceduralTaintAnalyzer(self._graph).analyze_entry(entry_id)
        from .models import TaintFlowRecord

        for step in taint.flows:
            result.taint_flows.append(
                TaintFlowRecord(
                    source_id=step.source_id,
                    target_id=step.target_id,
                    parameter=step.parameter,
                    provenance=step.provenance,
                    confidence=step.confidence,
                    line=step.line,
                )
            )

        reachable = [entry_id] + self._graph.reachable(entry_id)
        for node_id in reachable:
            node = self._graph.nodes.get(node_id)
            if not node:
                continue
            match = _match_sink(node.label, self._sinks)
            if not match:
                continue
            category, sink_name = match
            path = self._shortest_path(entry_id, node_id)
            edge = (
                self._graph.edge_between(path[-2], path[-1], relation=Relation.CALLS)
                if len(path) >= 2
                else None
            )
            provenance = edge.provenance if edge else Provenance.INFERRED
            hit = SinkHit(
                entry_id=entry_id,
                sink_id=node_id,
                category=category,
                sink_name=sink_name,
                provenance=provenance,
                path=path,
            )
            result.hits.append(hit)
        return result

    def analyze_all_entries(self) -> list[SinkAnalysisResult]:
        """Analyze all available entry points and return their sink-analysis results in sorted order."""
        entries = self._graph.entry_points
        if not entries:
            entries = {
                node_id
                for node_id, node in self._graph.nodes.items()
                if node.is_mcp_entry
            }
        if not entries:
            entries = set(self._graph.nodes)
        return [self.analyze_entry(entry_id) for entry_id in sorted(entries)]

    def _shortest_path(self, start: str, goal: str) -> list[str]:
        """Find the shortest call path from one graph node to another.
        
        Parameters:
        	start (str): Identifier of the starting node.
        	goal (str): Identifier of the destination node.
        
        Returns:
        	list[str]: The shortest path from `start` to `goal`, or a two-node path containing `start` and `goal` when no path is found.
        """
        if start == goal:
            return [start]
        queue: list[list[str]] = [[start]]
        visited = {start}
        while queue:
            path = queue.pop(0)
            current = path[-1]
            for callee in self._graph.get_callees(current):
                if callee in visited:
                    continue
                next_path = path + [callee]
                if callee == goal:
                    return next_path
                visited.add(callee)
                queue.append(next_path)
        return [start, goal]
