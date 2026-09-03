# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Bridge CodeGraph static analysis into BehavioralCodeAnalyzer."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional, Union

from ....threats.threats import ThreatMapping
from ....utils.log_format import sanitize_log_value, truncate
from ....utils.logging_config import get_logger
from ...analyzers.base import SecurityFinding
from ..interprocedural.call_graph_analyzer import CallGraphAnalyzer
from ..interprocedural.treesitter_call_graph import TreeSitterCallGraphAnalyzer
from ..context_extractor import FunctionContext
from ..native_analyzer import NativeAnalyzer
from .builder import GRAPH_SUPPORTED_LANGUAGES, CodeGraphBuilder
from .evidence import EvidenceFormatter
from .models import CodeGraph, SinkHit
from .sink_analyzer import SinkAnalysisResult, SinkAnalyzer
from .slicer import GraphSlicer
from .taint_context import populate_taint_fields

logger = get_logger(__name__)

_SINK_CATEGORY_TO_THREAT = {
    "command": "UNAUTHORIZED OR UNSOLICITED CODE EXECUTION",
    "eval": "UNAUTHORIZED OR UNSOLICITED CODE EXECUTION",
    "deserialization": "UNAUTHORIZED OR UNSOLICITED CODE EXECUTION",
    "file": "ARBITRARY RESOURCE READ/WRITE",
    "network": "UNAUTHORIZED OR UNSOLICITED NETWORK ACCESS",
    "sql": "DATA EXFILTRATION",
}

_GENERIC_LABELS = frozenset(
    {
        "file",
        "len",
        "str",
        "get",
        "append",
        "r.get",
        "results.append",
    }
)


def language_for_path(file_path: str) -> str:
    ext = Path(file_path).suffix.lower()
    return NativeAnalyzer.EXTENSION_MAP.get(ext, "unknown")


def is_graph_supported_language(language: str) -> bool:
    return language in GRAPH_SUPPORTED_LANGUAGES


def build_code_graph(
    cross_file_analyzer: Union[CallGraphAnalyzer, TreeSitterCallGraphAnalyzer],
    *,
    language: str,
    source_registry: dict[str, str] | None = None,
) -> CodeGraph:
    if source_registry:
        graphs = build_code_graphs_for_registry(source_registry)
        if language in graphs:
            return graphs[language]
        logger.debug(
            "code_graph language=%s not in registry graphs=%s fallback=call_graph_analyzer",
            language,
            sorted(graphs.keys()),
        )
    graph = CodeGraphBuilder.from_call_graph_analyzer(
        cross_file_analyzer,
        language=language,
        source_registry=source_registry,
    )
    logger.debug(
        "code_graph built_from_analyzer language=%s nodes=%d edges=%d entry_points=%d",
        language,
        len(graph.nodes),
        len(graph.edges),
        len(graph.entry_points),
    )
    return graph


def build_code_graphs_for_registry(
    source_registry: dict[str, str],
) -> dict[str, CodeGraph]:
    """Build language-scoped code graphs directly from a source registry."""
    from .cache import CodeGraphCache, graph_cache_for_scan

    buckets: dict[str, dict[str, str]] = {}
    for path, source in source_registry.items():
        lang = language_for_path(path)
        if not is_graph_supported_language(lang):
            continue
        buckets.setdefault(lang, {})[path] = source

    graphs: dict[str, CodeGraph] = {}
    cache = graph_cache_for_scan()
    skipped_unsupported = 0
    for path in source_registry:
        lang = language_for_path(path)
        if not is_graph_supported_language(lang):
            skipped_unsupported += 1

    for lang, files in buckets.items():
        if isinstance(cache, CodeGraphCache):
            merged = cache.get_merged(lang, files)
            if merged is not None:
                if not merged.source_registry:
                    merged.source_registry = dict(files)
                graphs[lang] = merged
                logger.debug(
                    "code_graph cache hit merged language=%s files=%d nodes=%d",
                    lang,
                    len(files),
                    len(merged.nodes),
                )
                continue
        builder = CodeGraphBuilder(cache=cache)
        for path, source in files.items():
            builder.add_file(Path(path), source)
        built = builder.build()
        if isinstance(cache, CodeGraphCache):
            cache.put_merged(lang, files, built)
        graphs[lang] = built

    if graphs or skipped_unsupported:
        logger.info(
            "code_graph registry built languages=%s files=%d skipped_unsupported=%d",
            sorted(graphs.keys()),
            len(source_registry),
            skipped_unsupported,
        )
    return graphs


def _resolved_path(file_path: str) -> Path:
    return Path(file_path).resolve()


def _node_file_path(node_id: str) -> Optional[Path]:
    if "::" not in node_id:
        return None
    return Path(node_id.split("::", 1)[0]).resolve()


def _decorator_registered_name(func_context: FunctionContext) -> str | None:
    """Return MCP decorator ``name=`` override when present."""
    for params in (func_context.decorator_params or {}).values():
        if isinstance(params, dict):
            custom = params.get("name")
            if isinstance(custom, str) and custom.strip():
                return custom.strip()
    return None


def resolve_entry_id(
    graph: CodeGraph,
    file_path: str,
    func_name: str,
    *,
    decorator_name: str | None = None,
) -> Optional[str]:
    """Map a FunctionContext to a graph node id."""
    resolved = _resolved_path(file_path)
    entry_match: Optional[str] = None
    name_match: Optional[str] = None
    candidates = [func_name]
    if decorator_name and decorator_name not in candidates:
        candidates.append(decorator_name)

    for candidate in candidates:
        for node_id, node in graph.nodes.items():
            label = node.label
            short = label.split(".")[-1] if "." in label else label
            if label != candidate and short != candidate:
                continue
            node_file = _node_file_path(node_id)
            if node_file is None or node_file != resolved:
                continue
            if node.is_mcp_entry:
                entry_match = node_id
            elif name_match is None:
                name_match = node_id
        if entry_match:
            break

    return entry_match or name_match


def _external_labels(path: list[str]) -> list[str]:
    labels: list[str] = []
    for node_id in path:
        if node_id.startswith("external::"):
            labels.append(node_id.split("::", 1)[-1])
    return labels


def is_actionable_sink_hit(hit: SinkHit) -> bool:
    """True when a sink hit is specific enough to raise without LLM."""
    externals = _external_labels(hit.path)
    if not externals:
        return False

    for label in externals:
        if label in _GENERIC_LABELS:
            continue
        if hit.category in _SINK_CATEGORY_TO_THREAT:
            return True
        if label in {"os.remove", "os.system", "os.rmdir", "shutil.rmtree", "subprocess.run"}:
            return True
        if label in {"fs.unlinkSync", "fs.unlink", "fs.rmSync", "File.delete", "unlink"}:
            return True
    return False


def enrich_with_cross_file_context(
    func_context: FunctionContext,
    file_path: str,
    call_graph_analyzer: CallGraphAnalyzer | TreeSitterCallGraphAnalyzer,
) -> None:
    """Populate cross-file reachability and parameter-flow metadata."""
    from ...analyzers.behavioral.dataflow.cross_file_dataflow_analyzer import (
        enrich_with_cross_file_context as _enrich,
    )

    _enrich(func_context, file_path, call_graph_analyzer)


def attach_graph_evidence(
    func_context: FunctionContext,
    graph: CodeGraph,
    entry_id: str,
) -> SinkAnalysisResult:
    """Annotate context and return sink analysis for one MCP function."""
    slice_ = GraphSlicer(graph).slice(entry_id)
    sink_result = SinkAnalyzer(graph).analyze_entry(entry_id)
    evidence = EvidenceFormatter(graph).format_combined(slice_, sink_result)
    func_context.dataflow_summary = dict(func_context.dataflow_summary or {})
    func_context.dataflow_summary["code_graph_evidence"] = evidence
    func_context.dataflow_summary["code_graph_entry_id"] = entry_id
    entry_node = graph.nodes.get(entry_id)
    if entry_node is not None:
        classic = entry_node.metadata.get("classic_dataflow")
        if classic:
            func_context.dataflow_summary["classic_dataflow"] = classic
    func_context.dataflow_summary["taint_flows"] = [
        flow.to_dict() for flow in sink_result.taint_flows
    ]
    populate_taint_fields(func_context)
    return sink_result


def create_sink_finding(
    hit: SinkHit,
    func_context: FunctionContext,
    file_path: str,
    *,
    evidence: str = "",
) -> Optional[SecurityFinding]:
    """Build a SecurityFinding from a deterministic graph sink hit."""
    threat_name = _SINK_CATEGORY_TO_THREAT.get(hit.category)
    if not threat_name:
        return None

    try:
        threat_info = ThreatMapping.get_threat_mapping("behavioral", threat_name)
    except ValueError:
        logger.debug(
            "code_graph unknown_threat_mapping category=%s threat=%s sink=%s",
            hit.category,
            threat_name,
            hit.sink_name,
        )
        return None

    path = " -> ".join(node_id.split("::")[-1] for node_id in hit.path)
    summary = (
        f"Line {func_context.line_number}: {threat_name} - "
        f"Deterministic sink '{hit.sink_name}' reachable via {path}"
    )

    return SecurityFinding(
        severity=threat_info["severity"],
        summary=summary,
        analyzer="Behavioral",
        threat_category=threat_info["scanner_category"],
        details={
            "function_name": func_context.name,
            "decorator_type": (
                func_context.decorator_types[0]
                if func_context.decorator_types
                else "unknown"
            ),
            "line_number": func_context.line_number,
            "source_file": file_path,
            "detection_method": "code_graph",
            "sink_category": hit.category,
            "sink_name": hit.sink_name,
            "sink_provenance": hit.provenance.value,
            "sink_path": path,
            "code_graph_evidence": evidence,
            "threat_type": threat_name,
        },
    )


def partition_functions_by_graph(
    func_contexts: list[FunctionContext],
    graph: CodeGraph,
    file_path: str,
) -> tuple[list[SecurityFinding], list[FunctionContext]]:
    """Attach graph evidence to every resolvable tool and return all for LLM alignment."""
    needs_llm: list[FunctionContext] = []
    resolved_count = 0
    unresolved_count = 0
    sink_hint_count = 0

    for func_context in func_contexts:
        decorator_name = _decorator_registered_name(func_context)
        entry_id = resolve_entry_id(
            graph,
            file_path,
            func_context.name,
            decorator_name=decorator_name,
        )
        if entry_id:
            resolved_count += 1
            sink_result = attach_graph_evidence(func_context, graph, entry_id)
            actionable = [
                hit for hit in sink_result.hits if is_actionable_sink_hit(hit)
            ]
            if actionable:
                sink_hint_count += len(actionable)
                func_context.dataflow_summary = dict(func_context.dataflow_summary or {})
                func_context.dataflow_summary["code_graph_sink_hints"] = [
                    {
                        "sink_name": hit.sink_name,
                        "category": hit.category,
                        "sink_path": " -> ".join(
                            node_id.split("::")[-1] for node_id in hit.path
                        ),
                        "provenance": hit.provenance.value,
                    }
                    for hit in actionable
                ]
        else:
            unresolved_count += 1
            logger.debug(
                "code_graph entry_unresolved file=%s function=%s decorator_name=%s",
                sanitize_log_value(file_path),
                func_context.name,
                decorator_name or "-",
            )

        needs_llm.append(func_context)

    logger.debug(
        "code_graph partition file=%s functions=%d resolved=%d unresolved=%d "
        "sink_hints=%d nodes=%d",
        sanitize_log_value(file_path),
        len(func_contexts),
        resolved_count,
        unresolved_count,
        sink_hint_count,
        len(graph.nodes),
    )

    return [], needs_llm
