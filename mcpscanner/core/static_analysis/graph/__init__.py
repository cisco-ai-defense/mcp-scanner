# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Deterministic code graph layer for behavioral security analysis.

Native replacement for Graphify-style static graph logic: build a provenance-tagged
call graph, slice bounded evidence, and detect sinks without an external dependency.
"""

from .builder import GRAPH_SUPPORTED_LANGUAGES, CodeGraphBuilder
from .cache import GRAPH_EXTRACTOR_VERSION, CodeGraphCache, GraphCache, graph_cache_for_scan
from .cfg_fusion import CFGFusionEngine, ParamBinding, extract_function_parameters
from .classic_dataflow import ClassicDataflowEngine, ClassicDataflowSummary, TREESITTER_LANGS
from .evidence import EvidenceFormatter
from .fixpoint import call_edges_without_superseded_external, prune_redundant_external_edges, refine_call_graph
from .interprocedural_taint import InterproceduralTaintAnalyzer
from .models import (
    GRAPH_IR_VERSION,
    CodeEdge,
    CodeGraph,
    CodeNode,
    Provenance,
    Relation,
    SinkHit,
    TaintFlowRecord,
)
from .integration import (
    attach_graph_evidence,
    build_code_graph,
    build_code_graphs_for_registry,
    create_sink_finding,
    is_actionable_sink_hit,
    is_graph_supported_language,
    language_for_path,
    partition_functions_by_graph,
    resolve_entry_id,
)
from .resolver import CrossFileSymbolResolver, module_id_for
from .sink_analyzer import SinkAnalysisResult, SinkAnalyzer
from .slicer import GraphSlice, GraphSlicer
from .taint_context import populate_taint_fields

__all__ = [
    "CFGFusionEngine",
    "ClassicDataflowEngine",
    "ClassicDataflowSummary",
    "CodeEdge",
    "CodeGraph",
    "CodeGraphBuilder",
    "CodeGraphCache",
    "CodeNode",
    "CrossFileSymbolResolver",
    "EvidenceFormatter",
    "GRAPH_EXTRACTOR_VERSION",
    "GRAPH_IR_VERSION",
    "GRAPH_SUPPORTED_LANGUAGES",
    "GraphCache",
    "GraphSlice",
    "GraphSlicer",
    "InterproceduralTaintAnalyzer",
    "ParamBinding",
    "Provenance",
    "Relation",
    "SinkAnalysisResult",
    "SinkAnalyzer",
    "SinkHit",
    "TREESITTER_LANGS",
    "TaintFlowRecord",
    "attach_graph_evidence",
    "build_code_graph",
    "build_code_graphs_for_registry",
    "call_edges_without_superseded_external",
    "create_sink_finding",
    "graph_cache_for_scan",
    "is_actionable_sink_hit",
    "is_graph_supported_language",
    "language_for_path",
    "module_id_for",
    "partition_functions_by_graph",
    "populate_taint_fields",
    "prune_redundant_external_edges",
    "refine_call_graph",
    "resolve_entry_id",
]
