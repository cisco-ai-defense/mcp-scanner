# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Summary-based call-graph fixpoint iteration (no full SSA)."""

from __future__ import annotations

import re
from pathlib import Path

from ....config.constants import MCPScannerConstants
from ....utils.logging_config import get_logger
from .dynamic_dispatch import is_dynamic_call_label
from .models import CodeEdge, CodeGraph, CodeNode, Provenance, Relation
from .resolver import CrossFileSymbolResolver
from .semantic_dispatch import (
    ProgramFacts,
    build_function_summaries,
)

logger = get_logger(__name__)


def _caller_file(node_id: str) -> str:
    if "::" in node_id:
        return node_id.split("::", 1)[0]
    return ""


def _edge_key(edge: CodeEdge) -> tuple[str, str, str | None]:
    return (edge.source, edge.target, edge.call_expression)


def refine_call_graph(
    graph: CodeGraph,
    *,
    language: str,
    files: dict[Path, str],
    known_functions: set[str],
    resolver: CrossFileSymbolResolver,
    max_rounds: int | None = None,
) -> int:
    """Iterate summary propagation + call-edge refinement until fixpoint.

    Returns the number of rounds executed.
    """
    rounds = (
        MCPScannerConstants.CODE_GRAPH_FIXPOINT_ROUNDS
        if max_rounds is None
        else max_rounds
    )
    if rounds <= 0 or not graph.source_registry:
        return 0

    facts = ProgramFacts()
    executed = 0

    for round_idx in range(rounds):
        summaries = build_function_summaries(
            graph,
            language=language,
            source_registry=graph.source_registry,
        )
        changed = facts.propagate_from_summaries(summaries, graph)
        resolver.set_program_facts(facts)

        refined = _refine_external_edges(
            graph,
            resolver=resolver,
            known_functions=known_functions,
            language=language,
            round_idx=round_idx,
        )
        if not changed and not refined:
            executed = round_idx + 1
            break
        executed = round_idx + 1
    else:
        executed = rounds

    if executed:
        logger.debug(
            "code_graph fixpoint rounds=%d nodes=%d call_edges=%d",
            executed,
            len(graph.nodes),
            sum(1 for e in graph.edges if e.relation == Relation.CALLS),
        )

    pruned = prune_redundant_external_edges(graph)
    if pruned:
        logger.debug("code_graph pruned %d redundant external call edges", pruned)
    return executed


def _refine_external_edges(
    graph: CodeGraph,
    *,
    resolver: CrossFileSymbolResolver,
    known_functions: set[str],
    language: str,
    round_idx: int,
) -> bool:
    """Re-resolve dynamic/external call edges using propagated facts."""
    changed = False
    existing = {_edge_key(e) for e in graph.edges if e.relation == Relation.CALLS}
    to_remove: list[CodeEdge] = []
    to_add: list[CodeEdge] = []

    for edge in list(graph.edges):
        if edge.relation != Relation.CALLS:
            continue
        if not edge.target.startswith("external::"):
            continue
        callee_label = edge.call_expression or edge.target.removeprefix("external::")
        if not is_dynamic_call_label(callee_label) and round_idx == 0:
            continue

        dispatch = resolver.resolve_callee_targets(
            edge.source,
            callee_label,
            known_functions,
        )
        if not dispatch.targets:
            continue

        resolved_any = False
        for target in dispatch.targets:
            if target.node_id.startswith("external::"):
                continue
            key = (edge.source, target.node_id, edge.call_expression)
            if key in existing:
                continue
            resolved_any = True
            to_add.append(
                CodeEdge(
                    source=edge.source,
                    target=target.node_id,
                    relation=Relation.CALLS,
                    provenance=dispatch.provenance,
                    confidence_score=target.confidence,
                    context=f"fixpoint_r{round_idx}:{target.context}",
                    call_expression=edge.call_expression,
                )
            )
            existing.add(key)
            _ensure_target_node(graph, target.node_id, language=language)

        if resolved_any:
            to_remove.append(edge)
            changed = True

    if to_remove or to_add:
        remove_set = {id(e) for e in to_remove}
        graph.edges = [e for e in graph.edges if id(e) not in remove_set]
        graph.edges.extend(to_add)
    return changed


def _external_expr_superseded_by_resolved(expr: str, resolved: str) -> bool:
    if not expr or not resolved:
        return False
    if expr == resolved:
        return True
    pattern = r"(?<![\w$.])" + re.escape(expr) + r"\s*\("
    return re.search(pattern, resolved) is not None


def call_edges_without_superseded_external(edges: list[CodeEdge]) -> list[CodeEdge]:
    """Return call edges, dropping external targets replaced by resolved edges."""
    if not edges:
        return edges
    resolved_exprs = {
        edge.call_expression
        for edge in edges
        if edge.call_expression and not edge.target.startswith("external::")
    }
    if not resolved_exprs:
        return edges

    kept: list[CodeEdge] = []
    for edge in edges:
        if not edge.target.startswith("external::"):
            kept.append(edge)
            continue
        expr = edge.call_expression or edge.target.removeprefix("external::")
        if expr in resolved_exprs:
            continue
        if any(
            _external_expr_superseded_by_resolved(expr, resolved)
            for resolved in resolved_exprs
        ):
            continue
        kept.append(edge)
    return kept


def prune_redundant_external_edges(graph: CodeGraph) -> int:
    """Drop external call edges superseded by a resolved edge from the same site."""
    by_source: dict[str, list[CodeEdge]] = {}
    for edge in graph.edges:
        if edge.relation != Relation.CALLS:
            continue
        by_source.setdefault(edge.source, []).append(edge)

    to_remove: list[CodeEdge] = []
    for edges in by_source.values():
        kept = call_edges_without_superseded_external(edges)
        kept_ids = {id(edge) for edge in kept}
        to_remove.extend(edge for edge in edges if id(edge) not in kept_ids)

    if not to_remove:
        return 0
    remove_ids = {id(edge) for edge in to_remove}
    graph.edges = [edge for edge in graph.edges if id(edge) not in remove_ids]
    return len(to_remove)


def _ensure_target_node(graph: CodeGraph, node_id: str, *, language: str) -> None:
    if node_id in graph.nodes:
        return
    if "::" not in node_id:
        return
    graph.add_node(
        CodeNode(
            node_id=node_id,
            label=node_id.split("::", 1)[-1],
            source_file=_caller_file(node_id),
            language=language,
            module_id=_caller_file(node_id),
            kind="function",
        )
    )
