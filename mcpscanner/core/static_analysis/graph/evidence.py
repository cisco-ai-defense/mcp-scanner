# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Format graph slices as LLM-ready evidence text."""

from __future__ import annotations

from .models import CodeGraph
from .sink_analyzer import SinkAnalysisResult
from .slicer import GraphSlice


class EvidenceFormatter:
    """Render deterministic graph evidence for alignment prompts."""

    def __init__(self, graph: CodeGraph, *, max_snippet_chars: int = 400) -> None:
        self._graph = graph
        self._max_snippet_chars = max_snippet_chars

    def _snippet_for(self, node_id: str) -> str | None:
        node = self._graph.nodes.get(node_id)
        if not node or not node.source_file:
            return None
        source = self._graph.source_registry.get(node.source_file)
        if not source or node.line is None:
            return None
        lines = source.splitlines()
        idx = max(0, node.line - 1)
        snippet = lines[idx] if idx < len(lines) else ""
        if len(snippet) > self._max_snippet_chars:
            return snippet[: self._max_snippet_chars] + "..."
        return snippet

    def format_slice(self, slice_: GraphSlice) -> str:
        lines = [
            "CODE GRAPH SLICE (deterministic static analysis)",
            f"Entry: {slice_.entry_id}",
            f"Nodes: {slice_.size} | Hops: {slice_.hop_limit}",
            "",
        ]
        for node_id in sorted(slice_.node_ids):
            node = self._graph.nodes.get(node_id)
            if not node:
                continue
            tag = "MCP_ENTRY" if node.is_mcp_entry else node.kind.upper()
            loc = f"{node.source_file}" if node.source_file else "external"
            line = f"- [{tag}] {node.label} ({loc})"
            snippet = self._snippet_for(node_id)
            if snippet:
                line += f"\n    snippet: {snippet.strip()}"
            lines.append(line)

        if slice_.edges:
            lines.append("")
            lines.append("Call edges:")
            for edge in slice_.edges:
                lines.append(
                    f"  {edge.source.split('::')[-1]} "
                    f"--{edge.relation.value}--> "
                    f"{edge.target.split('::')[-1]} "
                    f"[{edge.provenance.value}]"
                )
        return "\n".join(lines)

    def format_sinks(self, result: SinkAnalysisResult) -> str:
        if not result.hits:
            return "SINK ANALYSIS: no catalogued sinks reached."

        lines = ["SINK ANALYSIS (deterministic):", ""]
        for hit in result.hits:
            path = " -> ".join(pid.split("::")[-1] for pid in hit.path)
            lines.append(
                f"- {hit.category}: {hit.sink_name} "
                f"[{hit.provenance.value}] via {path}"
            )
        return "\n".join(lines)

    def format_combined(
        self,
        slice_: GraphSlice,
        sink_result: SinkAnalysisResult,
    ) -> str:
        return f"{self.format_slice(slice_)}\n\n{self.format_sinks(sink_result)}"
