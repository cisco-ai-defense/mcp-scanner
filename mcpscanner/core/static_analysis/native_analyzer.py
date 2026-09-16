# Copyright 2025 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""Native multi-language analyzer: language dispatch and shared extraction.

Per-language work lives in two backends chosen by
:meth:`NativeAnalyzer._detect_language`. The vocabulary they share -- language
tables, MCP SDK patterns, small pure helpers -- lives in
:mod:`.native_common`, some of which is re-exported here because callers
already import it from this module.
"""

from pathlib import Path
import ast
from dataclasses import dataclass, field
import logging
import re as _re

from typing import Any, Dict, List, Optional, Set

from tree_sitter import Language, Node, Parser

from .context_extractor import FunctionContext

from .native_common import (  # noqa: F401
    NativeAnalysisResult,
    TREE_SITTER_AVAILABLE,
    TaintInfo,
    _MCP_ANNOTATION_RE,
    _MCP_KNOWN_SERVER_CLASSES,
    _MCP_PREFILTER_RE,
    _MCP_SDK_MODULE_PREFIXES,
    _PREFILTER_LANGUAGES,
    _TS_NON_FUNCTION_NODE_TYPES,
    _classify_mcp_annotation,
    _get_language_module,
    _parse_name_from_annotations,
    _path_endswith_suffix,
)

from .native_python_backend import PythonBackendMixin
from .native_treesitter_backend import TreeSitterBackendMixin


@dataclass
class _CapabilityScan:
    """State threaded through the passes of one capability extraction.

    The passes accumulate into ``contexts`` and coordinate through ``seen``,
    which is keyed by ``(handle, capability_kind)``. Including the kind means
    a function registered as both a tool and a prompt -- legal in MCP --
    surfaces once per kind rather than being collapsed by whichever pass
    reached it first. The handle is whatever identifies the capability in
    that pass: a handler's start byte when we have the function, and a
    synthetic string when we only have a registration or a table entry.
    """

    tree: Any
    imports: List[str]
    func_types: Set[str]
    import_target_map: Dict[str, Any]
    cross_file_analyzer: Optional[Any]
    contexts: List[FunctionContext] = field(default_factory=list)
    seen: Set[Any] = field(default_factory=set)

    def claim(self, handle: Any, capability: str) -> bool:
        """Reserve a capability slot, returning False if already taken."""
        key = (handle, capability)
        if key in self.seen:
            return False
        self.seen.add(key)
        return True


class NativeAnalyzer(PythonBackendMixin, TreeSitterBackendMixin):
    """Native AST-based code analyzer - pure extraction, no hardcoded patterns.

    This analyzer extracts ALL code elements from source code via AST parsing.
    It does NOT apply any hardcoded security patterns - that's left to the LLM.

    Supports:
    - Python: Uses built-in ast module with full dataflow analysis
    - TypeScript/JavaScript/Go/Java/Kotlin/C#/Ruby/Rust/PHP: Uses tree-sitter with dataflow

    The output format matches FunctionContext for compatibility with
    the existing analysis pipeline.
    
    Key difference from basic NativeAnalyzer:
    - Performs taint tracking from function parameters
    - Detects security-relevant operations via dataflow (not hardcoded patterns)
    - Tracks parameter flows to calls, returns, and external operations
    """

    # File extension to language mapping
    EXTENSION_MAP = {
        # Python
        ".py": "python", ".pyw": "python",
        # TypeScript
        ".ts": "typescript", ".tsx": "typescript", ".mts": "typescript", ".cts": "typescript",
        # JavaScript
        ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
        # Go
        ".go": "go",
        # Java
        ".java": "java",
        # Kotlin
        ".kt": "kotlin", ".kts": "kotlin",
        # Swift
        ".swift": "swift",
        # C#
        ".cs": "c_sharp",
        # Ruby
        ".rb": "ruby", ".rake": "ruby", ".gemspec": "ruby",
        # Rust
        ".rs": "rust",
        # PHP
        ".php": "php", ".phtml": "php",
    }
    # Function node types per language (for tree-sitter)
    FUNCTION_NODE_TYPES = {
        "javascript": {"function_declaration", "function_expression", "arrow_function", "method_definition"},
        "typescript": {"function_declaration", "function_expression", "arrow_function", "method_definition"},
        "go": {"function_declaration", "method_declaration"},
        "java": {"method_declaration", "constructor_declaration"},
        "kotlin": {"function_declaration", "secondary_constructor", "primary_constructor", "lambda_literal", "anonymous_function"},
        "swift": {"function_declaration", "initializer_declaration"},
        "c_sharp": {"method_declaration", "constructor_declaration", "local_function_statement"},
        "ruby": {"method", "singleton_method"},
        "rust": {"function_item", "impl_item"},
        "php": {"function_definition", "method_declaration"},
    }
    # Class node types per language
    CLASS_NODE_TYPES = {
        "javascript": {"class_declaration"},
        "typescript": {"class_declaration"},
        "go": {"type_declaration"},
        "java": {"class_declaration", "interface_declaration"},
        "kotlin": {"class_declaration", "object_declaration"},
        "swift": {"class_declaration", "struct_declaration"},
        "c_sharp": {"class_declaration", "struct_declaration", "interface_declaration"},
        "ruby": {"class", "module"},
        "rust": {"struct_item", "impl_item"},
        "php": {"class_declaration", "interface_declaration"},
    }
    def __init__(self, source_code: str, file_path: str = "unknown"):
        """Initialize native analyzer.

        Args:
            source_code: Source code to analyze
            file_path: Path to source file (used for language detection)
        """
        self.source_code = source_code
        self.source_bytes = source_code.encode("utf-8")
        self.file_path = Path(file_path)
        self.lines = source_code.split("\n")
        self.logger = logging.getLogger(__name__)
        self.language = self._detect_language()
        
        # Taint tracking state (reset per function)
        self._taint_env: Dict[str, TaintInfo] = {}
    def _detect_language(self) -> str:
        """Detect programming language from file extension."""
        ext = self.file_path.suffix.lower()

        # Check extension map first
        if ext in self.EXTENSION_MAP:
            return self.EXTENSION_MAP[ext]

        # Fallback: try to parse as Python
        try:
            ast.parse(self.source_code)
            return "python"
        except SyntaxError:
            pass

        return "unknown"
    def analyze(self) -> NativeAnalysisResult:
        """Analyze source code and extract function contexts.

        Returns:
            NativeAnalysisResult with extracted functions
        """
        if self.language == "python":
            return self._analyze_python()
        elif self.language in self.FUNCTION_NODE_TYPES:
            # Use generic tree-sitter analyzer for all supported languages
            return self._analyze_tree_sitter()
        else:
            return NativeAnalysisResult(
                success=False,
                language=self.language,
                errors=[f"Unsupported language: {self.language}"],
            )
    def extract_all_function_contexts(self) -> List[FunctionContext]:
        """Extract contexts for ALL functions.

        This is the main entry point for fallback analysis.

        Returns:
            List of FunctionContext objects
        """
        result = self.analyze()
        return result.functions
    def extract_mcp_capability_contexts(
        self,
        cross_file_analyzer: Optional[Any] = None,
    ) -> List[FunctionContext]:
        """Extract contexts ONLY for functions exposed as MCP capabilities.

        The behavioral analyzer must reason about the *tools, prompts, and
        resources an MCP server exposes* — not about every helper function
        defined in the source file. ``extract_all_function_contexts()`` is
        the wrong primitive for that: it returns plain helpers like
        ``_validate`` alongside real tool callbacks, which causes the
        analyzer to spend LLM budget on non-capabilities and surface them in
        user-facing output as if they were tools.

        Detection runs in two complementary passes, sourced from each SDK's
        own README/quickstart so the patterns match real-world code:

        Pass 1 — **function-attached annotations** (function carries a
        sigil-led marker):

            * Python (FastMCP):    ``@mcp.tool``, ``.prompt``, ``.resource``
            * Java (Spring AI):    ``@Tool``, ``@McpTool``
            * C# (.NET SDK):       ``[McpServerTool]``, ``[Tool]``
            * Rust (rmcp):         ``#[tool]``, ``#[mcp::tool]``
            * PHP (php-mcp):       ``#[Tool(...)]``, ``#[McpTool(...)]``
            * Ruby (mcp-rb):       ``# @tool name: ...``

        Pass 2 — **call-site registrations** (function is registered by
        being passed to an SDK call):

            * TS SDK v1:           ``server.tool('name', schema, handler)``
            * TS SDK v2:           ``server.registerTool('name', {...}, handler)``
            * Go SDK:              ``mcp.AddTool(server, &mcp.Tool{...}, handler)``
            * Kotlin SDK:          ``server.addTool(name=..., ...) { req -> }``
              (handler is the *trailing lambda* outside ``arguments``)

        For each detected capability we return a ``FunctionContext`` whose
        ``name`` is preferred from the registered MCP name (e.g. ``'add'``)
        and whose ``decorator_types`` is tagged so downstream rendering can
        tell the function came from a capability registration vs. a plain
        function definition. Handlers are deduped by AST start-byte so the
        same function isn't returned twice if it's reachable via both
        passes.

        Plain helper functions that are not exposed as MCP capabilities are
        intentionally excluded. Languages without a tree-sitter parser
        return an empty list.
        """
        if self.language == "python":
            return self._py_extract_capability_contexts(
                cross_file_analyzer=cross_file_analyzer
            )

        parsed = self._parse_for_capabilities()
        if parsed is None:
            return []
        tree, imports = parsed

        scan = _CapabilityScan(
            tree=tree,
            imports=imports,
            func_types=self.FUNCTION_NODE_TYPES.get(self.language, set()),
            # Built once per extract call: cross-file resolution prefers
            # entries whose defining file path matches one of the calling
            # file's import targets, killing the "wrong same-named function
            # in node_modules wins" failure mode.
            import_target_map=self._build_import_target_map(
                imports,
                current_file=str(self.file_path) if self.file_path else None,
            ),
            cross_file_analyzer=cross_file_analyzer,
        )

        self._capabilities_from_annotations(scan)
        self._capabilities_from_registrations(scan)
        self._capabilities_from_endpoint_tables(scan)
        return scan.contexts

    def _parse_for_capabilities(self) -> Optional["tuple[Any, List[str]]"]:
        """Parse the file for capability extraction, or None if there is nothing to find.

        Returns None for the four cheap ways out: no MCP marker token
        anywhere in the bytes (Gap 12 -- skips the whole tree-sitter parse),
        no function node types for the language, no tree-sitter grammar
        installed, or a parse that raises.
        """
        if not self._has_mcp_markers():
            return None
        if self.language not in self.FUNCTION_NODE_TYPES:
            return None

        lang_mod = _get_language_module(self.language)
        if lang_mod is None:
            return None

        try:
            if self.language == "typescript":
                lang = Language(lang_mod.language_typescript())
            elif self.language == "php":
                lang = Language(lang_mod.language_php())
            else:
                lang = Language(lang_mod.language())

            parser = Parser(lang)
            tree = parser.parse(self.source_bytes)
            return tree, self._ts_extract_imports(tree.root_node)
        except Exception as e:
            self.logger.warning(
                f"MCP capability extraction failed for {self.file_path}: {e}"
            )
            return None

    def _capabilities_from_annotations(self, scan: _CapabilityScan) -> None:
        """Pass 1: functions carrying a sigil-led MCP marker."""
        # Gap 13: build the annotation index once, then look up annotations
        # per function via dict lookup instead of paying for
        # ``_ts_collect_function_annotations`` (a parent walk + sibling scan)
        # on every helper.
        annotation_index = self._ts_build_annotation_index(
            scan.tree.root_node, scan.func_types
        )

        def visit(node):
            if (
                node.type in scan.func_types
                and node.type not in _TS_NON_FUNCTION_NODE_TYPES
            ):
                annotations = annotation_index.get(node.start_byte, [])
                cap_kind = _classify_mcp_annotation(annotations, self.language)
                if cap_kind is not None and scan.claim(node.start_byte, cap_kind):
                    self._append_capability_context(
                        scan.contexts,
                        node,
                        scan.imports,
                        capability=cap_kind,
                        registered_name=_parse_name_from_annotations(annotations),
                        source_kind="annotation",
                    )
            for child in node.children:
                visit(child)

        visit(scan.tree.root_node)

    def _capabilities_from_registrations(self, scan: _CapabilityScan) -> None:
        """Pass 2: functions registered by being passed to an SDK call."""
        # Gap 4: require ``X.tool(...)`` / ``X.registerTool(...)`` to have
        # ``X`` resolve to an instance imported from the MCP SDK, so unrelated
        # builder DSLs (``myToolbar.tool('save')``) do not classify as MCP
        # registrations.
        mcp_instances = self._collect_mcp_instances(scan.tree.root_node, scan.imports)
        registrations = self._ts_find_mcp_registrations(
            scan.tree.root_node, trusted_receivers=mcp_instances
        )

        for reg in registrations:
            handler_node, cross_file_match = self._resolve_registration_handler(
                scan, reg
            )
            cap_kind = reg["capability"]
            handler_name = reg.get("handler_name")

            if handler_node is not None:
                if not scan.claim(handler_node.start_byte, cap_kind):
                    continue
                self._append_capability_context(
                    scan.contexts,
                    handler_node,
                    scan.imports,
                    capability=cap_kind,
                    registered_name=reg.get("name"),
                    # Tag templates with a ``.template`` subtype so reports can
                    # distinguish ``addResourceTemplate`` from ``addResource``.
                    source_kind=self._registration_source_kind(reg),
                )
                continue

            if cross_file_match is not None:
                # Cross-file hit: build a stub context that points at the
                # defining file/line via the call-graph node.
                cross_file_path, _ = cross_file_match
                if not scan.claim(f"{cross_file_path}::{handler_name}", cap_kind):
                    continue
                self._append_unresolved_capability(
                    scan.contexts,
                    capability=cap_kind,
                    registered_name=reg.get("name") or handler_name,
                    source_kind=self._registration_source_kind(reg, "cross_file"),
                    handler_name_hint=handler_name,
                    source_file=cross_file_path,
                )
                continue

            # Gap 8: emit an ``unresolved`` placeholder when the handler
            # cannot be located in-file or cross-file. Without this, the
            # capability is silently dropped and the alignment LLM never sees
            # it. The registration itself is the capability here, so it is
            # its own dedupe handle.
            if not (handler_name or reg.get("name")):
                continue
            if not scan.claim(id(reg), cap_kind):
                continue
            self._append_unresolved_capability(
                scan.contexts,
                capability=cap_kind,
                registered_name=reg.get("name") or handler_name,
                source_kind=self._registration_source_kind(reg, "unresolved"),
                handler_name_hint=handler_name,
            )

    def _resolve_registration_handler(
        self, scan: _CapabilityScan, reg: Dict[str, Any]
    ) -> "tuple[Optional[Any], Optional[tuple[str, Any]]]":
        """Locate a registration's handler, in-file first and then cross-file.

        Returns ``(handler_node, cross_file_match)``. Both None means the
        registration names a handler we cannot find anywhere, which Gap 8
        turns into a stub rather than a silent drop.
        """
        handler_node = reg.get("handler_node")
        handler_name = reg.get("handler_name")

        if handler_node is None and handler_name:
            handler_node = self._ts_find_function_def_by_name(
                scan.tree.root_node, handler_name, scan.func_types
            )
        if handler_node is not None:
            return handler_node, None

        # Gap 2: the resolver prefers matches whose path lines up with one of
        # the calling file's import targets, so a sibling
        # ``tests/fixtures/add.ts`` defining the same name does not win the
        # suffix race.
        if handler_name and scan.cross_file_analyzer is not None:
            return None, self._resolve_cross_file_handler(
                handler_name,
                scan.cross_file_analyzer,
                target_module_paths=scan.import_target_map.get(handler_name),
            )
        return None, None

    @staticmethod
    def _registration_source_kind(
        reg: Dict[str, Any], qualifier: Optional[str] = None
    ) -> str:
        """Build the ``registration[.qualifier][.template]`` provenance tag."""
        parts = ["registration"]
        if qualifier:
            parts.append(qualifier)
        if reg.get("template_subtype") == "template":
            parts.append("template")
        return ".".join(parts)

    def _capabilities_from_endpoint_tables(self, scan: _CapabilityScan) -> None:
        """Gap 8 extension: tool names declared in static endpoint tables.

        Covers literal ``name`` / ``alias`` fields, including arrays reached
        via ``for (const tool of api.endpoints)`` loops, in-file and
        cross-file.
        """
        table_names = self._ts_collect_static_endpoint_tool_names(
            scan.tree.root_node,
            import_target_map=scan.import_target_map,
            cross_file_analyzer=scan.cross_file_analyzer,
        )
        for tool_name in table_names:
            if not scan.claim(f"table:{tool_name}", "tool"):
                continue
            self._append_unresolved_capability(
                scan.contexts,
                capability="tool",
                registered_name=tool_name,
                source_kind="registration.table",
                handler_name_hint=tool_name,
            )
    def _resolve_cross_file_handler(
        self,
        handler_name: str,
        cross_file_analyzer: Any,
        *,
        target_module_paths: Optional[List[str]] = None,
    ) -> Optional["tuple[str, Any]"]:
        """Look ``handler_name`` up in a cross-file call graph (Gap 2).

        Both ``CallGraph`` (Python) and ``TSCallGraph`` (tree-sitter)
        store function definitions as ``Dict[str, Node]`` keyed by
        ``f"{file_path}::{name}"``. We start by collecting every entry
        whose key ends with ``::<handler_name>``.

        When ``target_module_paths`` is provided (typically built from
        the calling file's import map), we **prefer** matches whose
        defining file path lines up with one of the import targets — so
        a handler imported from ``./tools/add`` resolves to
        ``src/tools/add.ts`` even if a sibling
        ``tests/fixtures/add.ts`` happens to define the same name.

        Falls back to the legacy "first suffix match" behavior with a
        ``DEBUG`` log when the import map can't disambiguate.

        Returns ``(defining_file_path_str, node)`` for the chosen match,
        or ``None`` if the identifier isn't in the graph at all.
        """
        graph = getattr(cross_file_analyzer, "call_graph", None)
        if graph is None:
            return None
        functions = getattr(graph, "functions", None)
        if not functions:
            return None
        suffix = f"::{handler_name}"
        matches: List["tuple[str, Any]"] = []
        for full_name, node in functions.items():
            if full_name.endswith(suffix):
                file_path = full_name[: -len(suffix)]
                matches.append((file_path, node))
        if not matches:
            return None

        if target_module_paths:
            # Score each candidate by the longest matching import-target
            # suffix. Ties go to the first inserted match (insertion
            # order is stable across Python ≥3.7 dicts), which keeps
            # behavior deterministic.
            scored: List["tuple[int, str, Any]"] = []
            for fp, node in matches:
                best = 0
                for tgt in target_module_paths:
                    if _path_endswith_suffix(fp, tgt):
                        best = max(best, len(tgt))
                if best:
                    scored.append((best, fp, node))
            if scored:
                scored.sort(key=lambda t: t[0], reverse=True)
                return scored[0][1], scored[0][2]
            self.logger.debug(
                "Cross-file handler %r: import map suggested %r, "
                "but no call-graph entry matched. Falling back to first "
                "suffix match: %r.",
                handler_name,
                target_module_paths,
                matches[0][0],
            )
            return matches[0]

        if len(matches) > 1:
            # No import-map hint: stay with the legacy behavior, but
            # surface the ambiguity at DEBUG so it's at least visible
            # when scan results disagree with expectations.
            self.logger.debug(
                "Cross-file handler %r: %d call-graph entries match by "
                "suffix. Returning first: %r.",
                handler_name,
                len(matches),
                matches[0][0],
            )
        return matches[0]
    def _build_import_target_map(
        self,
        imports: Optional[List[str]],
        current_file: Optional[str] = None,
    ) -> Dict[str, List[str]]:
        """Build ``{bound_name: [path-suffix candidates]}`` from imports.

        Per-language import grammars are parsed with intentionally
        tolerant regexes — a malformed line can't break the whole pass
        because failures degrade gracefully into the legacy suffix-only
        cross-file resolution path (with a DEBUG log).

        Each candidate is a forward-slashed path-suffix without
        extension; e.g.::

            from .tools.add import addHandler   -> {"addHandler": ["tools/add"]}
            import tools.docs as docs           -> {"docs":       ["tools/docs"]}
            import { x } from "./tools/add"     -> {"x":          ["tools/add"]}
            import alias "github.com/foo/bar"   -> {"alias":      ["github.com/foo/bar"]}
        """
        out: Dict[str, List[str]] = {}
        if not imports:
            return out
        for stmt in imports:
            s = (stmt or "").strip()
            if not s:
                continue
            try:
                if self.language == "python":
                    self._py_collect_import_targets(s, out)
                elif self.language in ("typescript", "javascript"):
                    self._ts_collect_import_targets(s, out)
                elif self.language == "go":
                    self._go_collect_import_targets(s, out)
                # Other languages keep the legacy resolver behavior.
            except Exception:
                # Robust to malformed import lines — fall back to bare
                # suffix matching for affected symbols.
                self.logger.debug(
                    "Failed to parse import for target map: %r", s
                )
        return out
    def _go_collect_import_targets(
        self, stmt: str, out: Dict[str, List[str]]
    ) -> None:
        """Populate ``out`` from one Go import statement."""
        # ``import "github.com/foo/bar"`` or ``import alias "..."``.
        for m in _re.finditer(
            r"""(?:^|\b)(?:import\s+)?(?:(\w+)\s+)?['"]([^'"]+)['"]""",
            stmt,
        ):
            alias = m.group(1)
            path = m.group(2)
            if not path or "/" not in path and "." not in path:
                continue
            bound = alias or path.rsplit("/", 1)[-1]
            out.setdefault(bound, []).append(path)
    def _append_unresolved_capability(
        self,
        out: List[FunctionContext],
        *,
        capability: str,
        registered_name: Optional[str],
        source_kind: str,
        handler_name_hint: Optional[str] = None,
        source_file: Optional[str] = None,
    ) -> None:
        """Emit a stub ``FunctionContext`` for an unresolved handler.

        Gap 8 design: rather than silently dropping a registration whose
        handler we can't locate, surface a placeholder so downstream
        consumers (alignment LLM, reports) at least know a capability
        was registered. The stub carries a marker decorator tag
        (``<registration>.unresolved.<kind>``) so consumers can
        distinguish stub contexts from real handlers that just happen to
        have empty bodies.
        """
        name = registered_name or handler_name_hint or "<unresolved>"
        ctx = FunctionContext(
            name=name,
            decorator_types=[f"<{source_kind}>.{capability}"],
            imports=[],
            function_calls=[],
            assignments=[],
            control_flow={},
            parameter_flows=[],
            constants={},
            variable_dependencies={},
            has_file_operations=False,
            has_network_operations=False,
            has_subprocess_calls=False,
            has_eval_exec=False,
            has_dangerous_imports=False,
        )
        # Optional fields. Set them via attribute assignment because the
        # dataclass declares defaults — direct setattr is safe.
        ctx.docstring = None
        ctx.parameters = []
        ctx.return_type = None
        ctx.line_number = 0
        if source_file:
            # Stash the cross-file definition path on the context so the
            # behavioral analyzer / LLM client can show the user where
            # the unresolved handler actually lives.
            ctx.source_file = str(source_file)
        out.append(ctx)
    def _has_mcp_markers(self) -> bool:
        """Cheap byte-level prefilter (Gap 12).

        Returns ``True`` when the file's raw bytes contain at least one
        recognized MCP marker token. Files without any marker can be
        skipped entirely — neither tree-sitter parsed nor sent through
        the dataflow analyzer — saving significant time on large repos
        whose MCP surface is concentrated in a handful of files.

        The check runs against ``self.source_bytes`` so we don't pay
        UTF-8 decode cost; the regex is compiled once (module-level) and
        case-insensitive to absorb minor convention drift between SDKs.
        """
        if self.language not in _PREFILTER_LANGUAGES:
            # Languages outside our supported set can't be prefiltered
            # safely — fall through to whatever the language branch does.
            return True
        # Cache the prefilter result per-instance: the analyzer can be
        # consulted multiple times for the same file (annotation index,
        # registration walk, etc.) and one regex pass is enough.
        cached = getattr(self, "_mcp_prefilter_cache", None)
        if cached is not None:
            return cached
        result = bool(_MCP_PREFILTER_RE.search(self.source_bytes or b""))
        self._mcp_prefilter_cache = result
        return result
    def _append_capability_context(
        self,
        out: List[FunctionContext],
        handler_node: "Node",
        imports: List[str],
        *,
        capability: str,
        registered_name: Optional[str],
        source_kind: str,
    ) -> None:
        """Extract a FunctionContext for ``handler_node`` and tag it.

        Shared between the annotation-driven and call-site-driven passes
        so naming / decorator-tagging stays consistent.
        """
        # ``_ts_extract_functions`` (the existing top-level walker) tracks
        # the enclosing class via recursive context. Our directed walks
        # don't, so we recover the class name here by walking parents —
        # this keeps Java/C#/PHP method names class-qualified
        # (``CalcService.add``) and consistent with what
        # ``extract_all_function_contexts()`` returns.
        class_name = self._ts_find_enclosing_class_name(handler_node)

        try:
            ctx = self._ts_extract_function_context(
                handler_node, imports, class_name=class_name
            )
        except Exception as e:
            self.logger.debug(f"Failed to extract MCP handler context: {e}")
            return
        if ctx is None:
            return

        # When an inline (anonymous) handler is registered as
        # ``server.tool('add', ...)``, prefer the registered MCP name in
        # CLI/SDK output. For named functions we keep the symbol name
        # because that's also useful context; combine when both exist.
        if registered_name:
            if not ctx.name or ctx.name == "<anonymous>":
                ctx.name = registered_name
            elif registered_name != ctx.name and registered_name not in ctx.name:
                ctx.name = f"{registered_name} ({ctx.name})"

        cap_tag = f"<{source_kind}>.{capability}"
        if cap_tag not in ctx.decorator_types:
            ctx.decorator_types.append(cap_tag)

        out.append(ctx)
    def _collect_mcp_instances(
        self, root: "Node", imports: List[str]
    ) -> Set[str]:
        """Identify local names that bind to MCP server instances.

        Two-stage detection:

          1. Walk the file's imports / use statements for module
             specifiers belonging to a known MCP SDK
             (``@modelcontextprotocol/sdk``, ``fastmcp``, ``mcp.server``,
             ``modelcontextprotocol/go-sdk``, ``rmcp``, ...). The set of
             trusted SDK module specifiers is stored in
             ``_MCP_SDK_MODULE_PREFIXES``.
          2. Walk top-level variable declarations / parameter
             annotations / property accesses to map class instantiations
             of MCP server classes (``new McpServer(...)``,
             ``FastMCP(...)``, ``mcp.NewServer(...)``) onto local names.

        Returns the union of:
          * names bound to MCP server instances,
          * imported MCP SDK package aliases (Go's ``mcp``).

        When the import header is opaque (e.g., the source has no
        recognizable SDK import), returns an empty set so the caller can
        fall back to loose receiver matching rather than dropping every
        registration.
        """
        trusted: Set[str] = set()
        prefixes = _MCP_SDK_MODULE_PREFIXES.get(self.language, ())
        if not prefixes:
            return trusted

        # Stage 1: which import specifiers refer to MCP SDK modules?
        sdk_aliases: Set[str] = set()
        sdk_classes: Set[str] = set()
        for stmt in imports:
            stmt_lc = stmt.lower()
            if not any(p in stmt_lc for p in prefixes):
                continue

            # Try to extract the imported name(s) and any local alias.
            # Each language has a different import grammar so we use
            # tolerant regexes rather than re-parsing.
            for cls in _re.findall(r"\b([A-Z][A-Za-z0-9_]+)\b", stmt):
                if cls in _MCP_KNOWN_SERVER_CLASSES:
                    sdk_classes.add(cls)
            # ``import "...github.com/modelcontextprotocol/go-sdk/mcp"``
            # → expose alias ``mcp``; allow ``import alias "..."`` form too.
            if self.language == "go":
                m = _re.search(
                    r'^\s*(?:import\s+)?(?:([\w]+)\s+)?"[^"]*modelcontextprotocol[^"]*"',
                    stmt,
                )
                if m:
                    sdk_aliases.add(m.group(1) or "mcp")
            elif self.language == "python":
                # ``from fastmcp import FastMCP`` or
                # ``from mcp.server import Server``
                m = _re.match(
                    r"\s*from\s+([\w\.]+)\s+import\s+([\w\s,]+)", stmt
                )
                if m:
                    for sym in m.group(2).split(","):
                        sym = sym.strip().split(" as ")[0].strip()
                        if sym:
                            sdk_classes.add(sym)
            elif self.language == "kotlin":
                # ``import io.modelcontextprotocol.kotlin.sdk.server.Server``
                m = _re.search(r"\.(\w+)\s*$", stmt)
                if m:
                    sdk_classes.add(m.group(1))

        trusted.update(sdk_aliases)

        # Stage 2: walk the AST for instantiations bound to local names.
        def visit(node: "Node"):
            # JS/TS: ``const server = new McpServer(...)``
            if node.type in ("variable_declarator", "lexical_declaration"):
                name_node = node.child_by_field_name("name")
                value_node = node.child_by_field_name("value")
                if name_node is not None and value_node is not None:
                    if self._ts_is_mcp_instantiation(value_node, sdk_classes):
                        trusted.add(self._ts_get_node_text(name_node))

            # Go: ``server := mcp.NewServer(...)`` parses as
            # ``short_var_declaration`` with ``left`` (identifier) and
            # ``right`` (call_expression).
            if node.type == "short_var_declaration":
                left = node.child_by_field_name("left")
                right = node.child_by_field_name("right")
                if left is not None and right is not None:
                    if self._ts_is_mcp_factory_call(right, sdk_aliases):
                        trusted.add(self._ts_get_node_text(left))

            # Python/Kotlin function/method parameters declared with an
            # MCP server type annotation (``server: Server`` /
            # ``def f(server: Server)``).
            if node.type in (
                "parameter",
                "formal_parameter",
                "typed_parameter",
                "function_parameter",
                "value_parameter",
            ):
                pname = node.child_by_field_name("name")
                ptype = node.child_by_field_name("type")
                if pname is not None and ptype is not None:
                    type_text = self._ts_get_node_text(ptype).strip()
                    if (
                        type_text in sdk_classes
                        or type_text.split(".")[-1] in sdk_classes
                    ):
                        trusted.add(self._ts_get_node_text(pname))

            # Python: ``mcp = FastMCP("demo")`` parses as ``assignment``
            # with ``left`` (identifier) and ``right`` (call_expression).
            if node.type == "assignment":
                left = node.child_by_field_name("left")
                right = node.child_by_field_name("right")
                if left is not None and right is not None:
                    if self._ts_is_mcp_instantiation(right, sdk_classes):
                        trusted.add(self._ts_get_node_text(left))

            for child in node.children:
                visit(child)

        visit(root)
        return trusted
    def _analyze_python(self) -> NativeAnalysisResult:
        """Analyze Python source code using built-in ast module."""
        functions = []
        errors = []
        partial = False

        try:
            tree = ast.parse(self.source_code, filename=str(self.file_path))
            module_imports = self._py_extract_imports(tree)

            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    try:
                        ctx = self._py_extract_function(node, module_imports)
                        functions.append(ctx)
                    except Exception as e:
                        errors.append(f"Failed to extract {node.name}: {e}")
                        partial = True

            return NativeAnalysisResult(
                success=True,
                language="python",
                functions=functions,
                errors=errors,
                partial=partial,
            )

        except SyntaxError as e:
            return NativeAnalysisResult(
                success=False,
                language="python",
                errors=[f"Syntax error: {e}"],
            )
    def _analyze_tree_sitter(self) -> NativeAnalysisResult:
        """Analyze source code using tree-sitter AST (generic for all languages)."""
        # Get the language module
        lang_mod = _get_language_module(self.language)
        if lang_mod is None:
            return NativeAnalysisResult(
                success=False,
                language=self.language,
                errors=[f"tree-sitter-{self.language} not available. Install: pip install tree-sitter-{self.language.replace('_', '-')}"],
            )

        functions = []
        errors = []

        try:
            # Get the language object
            if self.language == "typescript":
                lang = Language(lang_mod.language_typescript())
            elif self.language == "php":
                lang = Language(lang_mod.language_php())
            else:
                lang = Language(lang_mod.language())

            parser = Parser(lang)
            tree = parser.parse(self.source_bytes)

            # Extract imports from AST
            imports = self._ts_extract_imports(tree.root_node)

            # Extract all functions from AST
            self._ts_extract_functions(tree.root_node, imports, functions)

            return NativeAnalysisResult(
                success=True,
                language=self.language,
                functions=functions,
                errors=errors,
            )

        except Exception as e:
            return NativeAnalysisResult(
                success=False,
                language=self.language,
                errors=[f"Parse error: {e}"],
            )
