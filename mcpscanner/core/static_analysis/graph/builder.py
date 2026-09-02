# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Build a unified CodeGraph from existing call-graph analyzers."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ....utils.logging_config import get_logger
from ..interprocedural.call_graph_analyzer import CallGraph, CallGraphAnalyzer
from ..interprocedural.treesitter_call_graph import (
    TSCallGraph,
    TreeSitterCallGraphAnalyzer,
)
from ..native_analyzer import NativeAnalyzer
from .cache import GRAPH_EXTRACTOR_VERSION, CodeGraphCache, GraphCache, graph_cache_for_scan
from .cfg_fusion import extract_function_parameters
from .fixpoint import refine_call_graph
from .models import CodeEdge, CodeGraph, CodeNode, Provenance, Relation
from .resolver import CrossFileSymbolResolver, module_id_for
from .semantic_dispatch import DispatchResult, DispatchTarget

logger = get_logger(__name__)

_LANG_FOR_TS = {
    "javascript": "javascript",
    "typescript": "typescript",
    "go": "go",
    "rust": "rust",
    "java": "java",
    "kotlin": "kotlin",
    "c_sharp": "c_sharp",
    "ruby": "ruby",
    "php": "php",
}

GRAPH_SUPPORTED_LANGUAGES = frozenset({"python", *_LANG_FOR_TS})


def _caller_file(node_id: str) -> str:
    """Extract the file path prefix from a function identifier.
    
    Parameters:
        node_id (str): Function identifier that may include a file path followed by ``::``.
    
    Returns:
        str: The file path prefix, or an empty string if the identifier has no ``::`` separator.
    """
    if "::" in node_id:
        return node_id.split("::", 1)[0]
    return ""


class CodeGraphBuilder:
    """Merge Python and tree-sitter call graphs into one CodeGraph."""

    def __init__(
        self,
        *,
        cache: GraphCache[CodeGraph] | CodeGraphCache | None = None,
    ) -> None:
        self._files: dict[Path, str] = {}
        if cache is None:
            self._cache: GraphCache[CodeGraph] | CodeGraphCache = GraphCache[CodeGraph](
                version=GRAPH_EXTRACTOR_VERSION
            )
        else:
            self._cache = cache

    @staticmethod
    def _language_for_path(path: Path) -> str:
        """Determine the supported graph language for a file path.
        
        Parameters:
        	path (Path): The file path whose extension identifies the language.
        
        Returns:
        	str: The mapped language name, or "unknown" when the extension is unsupported.
        """
        ext = path.suffix.lower()
        return NativeAnalyzer.EXTENSION_MAP.get(ext, "unknown")

    def add_file(self, file_path: Path, source_code: str) -> None:
        """Store source code for a resolved file path."""
        self._files[file_path.resolve()] = source_code

    def add_path(self, file_path: Path) -> None:
        """Read a source file and add its contents to the builder under its resolved path."""
        resolved = file_path.resolve()
        self._files[resolved] = resolved.read_text(encoding="utf-8", errors="replace")

    def build(self) -> CodeGraph:
        """
        Build a unified code graph from the registered source files.
        
        Returns:
            CodeGraph: The combined graph of analyzed files.
        """
        graph = CodeGraph()
        if not self._files:
            return graph

        graph.source_registry = {str(path): source for path, source in self._files.items()}

        py_files: dict[Path, str] = {}
        ts_buckets: dict[str, dict[Path, str]] = {}

        for path, source in self._files.items():
            lang = self._language_for_path(path)
            if lang == "python":
                py_files[path] = source
            elif lang in _LANG_FOR_TS:
                ts_buckets.setdefault(lang, {})[path] = source

        if py_files:
            self._ingest_python(py_files, graph)
        for lang, files in ts_buckets.items():
            self._ingest_treesitter(lang, files, graph)

        if graph.language is None:
            if py_files:
                graph.language = "python"
            elif ts_buckets:
                graph.language = next(iter(ts_buckets))

        logger.info(
            "code_graph built nodes=%d edges=%d entry_points=%d language=%s",
            len(graph.nodes),
            len(graph.edges),
            len(graph.entry_points),
            graph.language,
        )
        return graph

    def _cached_graph_for_files(
        self,
        files: dict[Path, str],
        language: str,
        build_fn,
    ) -> CodeGraph:
        """
        Build a graph for a file collection, reusing cached results for single-file builds.
        
        Parameters:
            files (dict[Path, str]): Source files keyed by their paths.
            language (str): Language assigned to the resulting graph.
            build_fn (Callable): Function that builds a graph from a mapping of file paths to source code.
        
        Returns:
            CodeGraph: The merged graph for the provided files.
        """
        if len(files) > 1:
            return build_fn(files)

        partial = CodeGraph(language=language)
        partial.source_registry = {str(path): source for path, source in files.items()}
        for path, source in files.items():
            cached = self._cache.get(str(path), source)
            if cached is not None:
                self._merge_graphs(partial, cached)
                continue
            single = build_fn({path: source})
            self._cache.put(str(path), source, single)
            self._merge_graphs(partial, single)
        return partial

    def _merge_graphs(self, target: CodeGraph, other: CodeGraph) -> None:
        """Merge nodes, edges, entry points, and taint flows from one code graph into another.
        
        Existing nodes in the target graph are preserved when both graphs contain the same node ID.
        """
        for node_id, node in other.nodes.items():
            if node_id not in target.nodes:
                target.add_node(node)
        target.edges.extend(other.edges)
        target.entry_points.update(other.entry_points)
        target.taint_flows.extend(other.taint_flows)

    def _ingest_python(self, files: dict[Path, str], graph: CodeGraph) -> None:
        def _build(single_files: dict[Path, str]) -> CodeGraph:
            """
            Build a Python code graph from the provided source files.
            
            Parameters:
                single_files (dict[Path, str]): Source code keyed by file path.
            
            Returns:
                CodeGraph: The merged Python code graph with cross-file call resolution.
            """
            analyzer = CallGraphAnalyzer()
            for path, source in single_files.items():
                analyzer.add_file(path, source)
            raw = analyzer.build_call_graph()
            partial = CodeGraph(language="python")
            partial.source_registry = {str(p): s for p, s in single_files.items()}
            resolver = CrossFileSymbolResolver(
                single_files,
                language="python",
                function_nodes=raw.functions,
            )
            self._merge_call_graph(
                raw,
                partial,
                language="python",
                mcp_entries=raw.mcp_entry_points,
                resolver=resolver,
            )
            return partial

        merged = self._cached_graph_for_files(files, "python", _build)
        self._merge_graphs(graph, merged)

    def _ingest_treesitter(
        self,
        language: str,
        files: dict[Path, str],
        graph: CodeGraph,
    ) -> None:
        """
        Ingest tree-sitter analysis results for source files into a graph.
        
        Parameters:
            language (str): Graph language associated with the source files.
            files (dict[Path, str]): Source files to analyze, keyed by path.
            graph (CodeGraph): Graph to which the analyzed results are added.
        """
        ts_lang = _LANG_FOR_TS.get(language, language)

        def _build(single_files: dict[Path, str]) -> CodeGraph:
            """
            Build a partial code graph from the supplied source files.
            
            Parameters:
                single_files (dict[Path, str]): Source files to analyze.
            
            Returns:
                CodeGraph: The merged graph for the supplied files.
            """
            analyzer = TreeSitterCallGraphAnalyzer(ts_lang)
            for path, source in single_files.items():
                analyzer.add_file(path, source)
            raw = analyzer.build_call_graph()
            partial = CodeGraph(language=language)
            partial.source_registry = {str(p): s for p, s in single_files.items()}
            resolver = CrossFileSymbolResolver(
                single_files,
                language=language,
                function_nodes=raw.functions,
            )
            self._merge_call_graph(
                raw,
                partial,
                language=language,
                mcp_entries=set(raw.entry_points),
                resolver=resolver,
            )
            return partial

        merged = self._cached_graph_for_files(files, language, _build)
        self._merge_graphs(graph, merged)

    def _merge_call_graph(
        self,
        raw: CallGraph | TSCallGraph,
        graph: CodeGraph,
        *,
        language: str,
        mcp_entries: set[str],
        resolver: CrossFileSymbolResolver | None = None,
    ) -> None:
        """Merge analyzed functions, calls, imports, and entry points into a code graph.
        
        Parameters:
            raw (CallGraph | TSCallGraph): Call graph data to merge.
            graph (CodeGraph): Destination graph.
            language (str): Language associated with the analyzed graph.
            mcp_entries (set[str]): Function identifiers designated as MCP entry points.
            resolver (CrossFileSymbolResolver | None): Optional resolver for cross-file call targets and imports.
        """
        known_functions = set(raw.functions.keys())
        func_nodes = dict(raw.functions)

        for full_name, func_node in func_nodes.items():
            file_path = _caller_file(full_name)
            short = full_name.split("::", 1)[-1]
            params = extract_function_parameters(func_node, language)
            graph.add_node(
                CodeNode(
                    node_id=full_name,
                    label=short,
                    source_file=file_path,
                    language=language,
                    module_id=module_id_for(file_path) if file_path else "",
                    is_mcp_entry=full_name in mcp_entries,
                    metadata={"parameters": params},
                )
            )

        for caller, callee in raw.calls:
            callee_label = callee.split("::")[-1] if "::" in callee else callee
            if resolver is not None:
                dispatch = resolver.resolve_callee_targets(caller, callee_label, known_functions)
                if not dispatch.targets:
                    resolved, provenance, confidence, context = resolver.resolve_callee(
                        caller, callee_label, known_functions
                    )
                    dispatch = DispatchResult(
                        targets=[
                            DispatchTarget(
                                node_id=resolved,
                                confidence=confidence,
                                context=context or "static",
                            )
                        ]
                    )
                    dispatch_provenance = provenance
                else:
                    dispatch_provenance = dispatch.provenance
                for target in dispatch.targets:
                    graph.add_edge(
                        CodeEdge(
                            source=caller,
                            target=target.node_id,
                            relation=Relation.CALLS,
                            provenance=dispatch_provenance,
                            confidence_score=target.confidence,
                            context=target.context,
                            call_expression=callee_label,
                        )
                    )
                    self._ensure_call_target_node(
                        graph,
                        target.node_id,
                        callee_label=callee_label,
                        language=language,
                        fallback_provenance=dispatch_provenance,
                        fallback_confidence=target.confidence,
                        fallback_context=target.context,
                    )
                continue
            resolved, provenance, confidence, context = (
                callee,
                Provenance.INFERRED,
                0.75,
                None,
            )
            graph.add_edge(
                CodeEdge(
                    source=caller,
                    target=resolved,
                    relation=Relation.CALLS,
                    provenance=provenance,
                    confidence_score=confidence,
                    context=context,
                    call_expression=callee_label,
                )
            )
            self._ensure_call_target_node(
                graph,
                resolved,
                callee_label=callee_label,
                language=language,
                fallback_provenance=provenance,
                fallback_confidence=confidence,
                fallback_context=context,
            )

        if resolver is not None:
            for edge in resolver.import_edges():
                graph.add_edge(edge)

        for entry in mcp_entries:
            if entry in graph.nodes:
                graph.entry_points.add(entry)

        if resolver is not None and graph.source_registry:
            refine_call_graph(
                graph,
                language=language,
                files=resolver.files,
                known_functions=known_functions,
                resolver=resolver,
            )

    @staticmethod
    def _ensure_call_target_node(
        graph: CodeGraph,
        resolved: str,
        *,
        callee_label: str,
        language: str,
        fallback_provenance: Provenance,
        fallback_confidence: float,
        fallback_context: str | None,
    ) -> None:
        """
        Ensure that a resolved call target has a corresponding graph node, creating an external sink for unresolved targets.
        
        Parameters:
            resolved (str): Identifier of the resolved call target.
            callee_label (str): Display label for an unresolved external target.
            language (str): Language associated with the created node.
            fallback_provenance (Provenance): Provenance assigned when redirecting an unresolved call edge.
            fallback_confidence (float): Confidence assigned when redirecting an unresolved call edge.
            fallback_context (str | None): Context assigned when redirecting an unresolved call edge.
        """
        if resolved in graph.nodes:
            return
        if "::" in resolved:
            graph.add_node(
                CodeNode(
                    node_id=resolved,
                    label=resolved.split("::", 1)[-1],
                    source_file=_caller_file(resolved),
                    language=language,
                    module_id=module_id_for(_caller_file(resolved))
                    if _caller_file(resolved)
                    else "",
                    kind="external" if resolved.startswith("external::") else "function",
                )
            )
            return
        sink_id = f"external::{callee_label}"
        graph.add_node(
            CodeNode(
                node_id=sink_id,
                label=callee_label,
                source_file="",
                language=language,
                kind="external",
            )
        )
        if graph.edges:
            last = graph.edges[-1]
            if last.target == resolved:
                graph.edges[-1] = CodeEdge(
                    source=last.source,
                    target=sink_id,
                    relation=Relation.CALLS,
                    provenance=fallback_provenance,
                    confidence_score=fallback_confidence,
                    context=fallback_context,
                    call_expression=last.call_expression,
                )

    @classmethod
    def from_directory(
        cls,
        root: Path,
        *,
        extensions: set[str] | None = None,
        cache: GraphCache[CodeGraph] | CodeGraphCache | None = None,
    ) -> CodeGraph:
        """
        Build a code graph from supported source files under a directory.
        
        Parameters:
            root (Path): Directory to scan recursively.
            extensions (set[str] | None): File extensions to include; when omitted, all
                supported graph-language extensions are included.
        
        Returns:
            CodeGraph: The combined graph for the readable matching files.
        """
        builder = cls(cache=cache or graph_cache_for_scan())
        allowed = extensions or {
            ext
            for ext, lang in NativeAnalyzer.EXTENSION_MAP.items()
            if lang in GRAPH_SUPPORTED_LANGUAGES
        }
        for path in sorted(root.rglob("*")):
            if not path.is_file() or path.suffix not in allowed:
                continue
            try:
                builder.add_path(path)
            except OSError:
                continue
        return builder.build()

    @classmethod
    def from_call_graph_analyzer(
        cls,
        analyzer: CallGraphAnalyzer | TreeSitterCallGraphAnalyzer,
        *,
        language: str,
        source_registry: dict[str, str] | None = None,
    ) -> CodeGraph:
        """
        Build a unified code graph from an existing call-graph analyzer.
        
        Parameters:
        	analyzer: Analyzer whose call graph should be converted.
        	language: Language associated with the analyzed source.
        	source_registry: Optional mapping of source file paths to their contents, used for cross-file symbol resolution.
        
        Returns:
        	CodeGraph: The converted code graph.
        """
        graph = CodeGraph()
        builder = cls()
        raw = analyzer.build_call_graph()
        mcp_entries = set(getattr(raw, "mcp_entry_points", set()) or set())
        if not mcp_entries:
            mcp_entries = set(getattr(raw, "entry_points", set()) or set())
        files: dict[Path, str] = {}
        if source_registry:
            graph.source_registry = dict(source_registry)
            files = {Path(path): src for path, src in source_registry.items()}
        resolver = (
            CrossFileSymbolResolver(files, language=language, function_nodes=raw.functions)
            if files
            else None
        )
        builder._merge_call_graph(
            raw,
            graph,
            language=language,
            mcp_entries=mcp_entries,
            resolver=resolver,
        )
        return graph
