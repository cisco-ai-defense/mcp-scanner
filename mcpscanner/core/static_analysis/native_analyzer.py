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

"""Native Code Analyzer - AST-based multi-language analyzer.

This module provides code analyzer that works when the primary
ContextExtractor fails or cannot understand the code structure.
It supports MCP servers written in multiple languages.

Supported languages and MCP SDK patterns:
- Python (via built-in ast module): @mcp.tool(), @mcp.resource(), @mcp.prompt()
- TypeScript/JavaScript (via tree-sitter): server.registerTool(), server.tool()
- Go (via tree-sitter): mcp.AddTool(server, &mcp.Tool{...}, handler)
- Java/Spring (via tree-sitter): @Tool, @ToolParam annotations on @Service classes
- Kotlin (via tree-sitter): server.addTool(name, description, inputSchema) { handler }
- C#/.NET (via tree-sitter): [McpServerTool], [Description] on [McpServerToolType] classes
- Rust (via tree-sitter): #[tool], #[tool_router] macros (rmcp crate)
- Ruby (via tree-sitter): # @tool comment annotations
- PHP (via tree-sitter): @Tool annotations in docblocks
- Swift (via tree-sitter): General function analysis

Key features:
- Pure AST extraction - NO hardcoded patterns
- Extracts ALL code elements and lets LLM analyze them
- Comprehensive taint tracking for security analysis
- Cross-language security operation detection (command injection, SQL injection, etc.)
- Outputs the same FunctionContext format as the primary analyzer
- Works regardless of decorator patterns used
"""

import ast
import logging
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union

from .context_extractor import FunctionContext
from .parser.python_parser import PythonParser
from .dataflow.forward_analysis import ForwardDataflowAnalysis
from .dataflow.treesitter_analysis import TreeSitterDataflowAnalysis
from .taint.tracker import TaintStatus


# Simple TaintInfo for fallback (when full analysis fails)
@dataclass
class TaintInfo:
    """Simple taint information for fallback analysis."""
    status: TaintStatus = TaintStatus.UNTAINTED
    sources: Set[str] = field(default_factory=set)
    
    def is_tainted(self) -> bool:
        return self.status == TaintStatus.TAINTED
    
    def merge(self, other: "TaintInfo") -> "TaintInfo":
        """Merge two taint infos (union of taints)."""
        if self.status == TaintStatus.TAINTED or other.status == TaintStatus.TAINTED:
            return TaintInfo(
                status=TaintStatus.TAINTED,
                sources=self.sources | other.sources
            )
        return TaintInfo(status=self.status, sources=self.sources.copy())

# Tree-sitter imports - each language is optional
from tree_sitter import Language, Parser, Node
TREE_SITTER_AVAILABLE = True

# Language modules - imported lazily
_LANGUAGE_MODULES: Dict[str, Any] = {}

def _get_language_module(lang: str) -> Optional[Any]:
    """Lazily import tree-sitter language module."""
    if lang in _LANGUAGE_MODULES:
        return _LANGUAGE_MODULES[lang]
    
    try:
        if lang == "javascript":
            import tree_sitter_javascript as mod
        elif lang == "typescript":
            import tree_sitter_typescript as mod
        elif lang == "go":
            import tree_sitter_go as mod
        elif lang == "java":
            import tree_sitter_java as mod
        elif lang == "kotlin":
            import tree_sitter_kotlin as mod
        elif lang == "swift":
            import tree_sitter_swift as mod
        elif lang == "c_sharp":
            import tree_sitter_c_sharp as mod
        elif lang == "ruby":
            import tree_sitter_ruby as mod
        elif lang == "rust":
            import tree_sitter_rust as mod
        elif lang == "php":
            import tree_sitter_php as mod
        else:
            return None
        _LANGUAGE_MODULES[lang] = mod
        return mod
    except ImportError:
        _LANGUAGE_MODULES[lang] = None
        return None


# Method names that MCP SDKs use to register tools/prompts/resources at
# call sites. Lowercased; the observed call name is lowercased before
# comparing. Verified against the upstream SDK READMEs (TS SDK v1/v2, Go
# SDK ``mcp.AddTool``, Kotlin SDK ``server.addTool``) so the list stays
# narrow and avoids matching unrelated ``.tool``/``.prompt`` collisions.
_MCP_REGISTRATION_METHODS: Set[str] = {
    "tool",
    "prompt",
    "resource",
    "registertool",
    "registerprompt",
    "registerresource",
    "addtool",
    "addprompt",
    "addresource",
}


# Canonical capability suffixes used in Python decorators (e.g. `@mcp.tool`,
# `@hello_mcp.prompt`, or the bare `@resource`).
_PY_MCP_CAPABILITY_TAGS = ("tool", "prompt", "resource")


# Some grammars list class-like constructs in their "function types" set
# (most notably Rust's ``impl_item`` covers both impl blocks *and* the
# methods inside them). Pass 1 of capability detection must skip the
# wrapper because it isn't a callable surface — but recursion will still
# visit the inner ``function_item`` children, so real functions inside
# ``impl Foo { ... }`` are not lost.
_TS_NON_FUNCTION_NODE_TYPES: Set[str] = {
    "impl_item",
}


# Compiled once: matches an annotation/attribute/macro sigil followed by an
# identifier we want to inspect. Covers:
#   @Tool            Java/Spring AI
#   @McpTool         Spring AI MCP annotations
#   [McpServerTool]  C# attributes
#   #[tool]          Rust attribute macros (and `#[mcp::tool]`)
#   #[Tool]          PHP 8 attributes
#   # @tool          Ruby comment-style annotation
import re as _re  # local alias avoids polluting wider module namespace
_MCP_ANNOTATION_RE = _re.compile(
    r"""
    (?:                       # one of the annotation sigils
        @\#?                  #   @ or @# (rare)
      | \#\s*\[               #   # [  (Rust / PHP 8 — note '# ' before '[')
      | \[                    #   [  (C#)
      | \#\s*@                #   # @ (Ruby docblock-style)
    )
    \s*
    (?:[\w]+::)*              # optional namespace path like ``mcp::``
    ([A-Za-z_][\w]*)          # ← captured: the identifier
    """,
    _re.VERBOSE,
)

# Captures the value assigned to a ``name = ...``/``name: ...`` argument on
# an annotation or registration call. Used to surface the registered MCP
# capability name (e.g. ``add`` from ``@Tool(name="add")``).
_MCP_NAME_ARG_RE = _re.compile(
    r"""\bname\s*[=:]\s*['"]([^'"]+)['"]""",
)


def _strip_string_quotes(s: str) -> str:
    """Strip matching surrounding quotes from a tree-sitter string node text."""
    s = s.strip()
    if len(s) >= 2 and s[0] in ('"', "'", "`") and s[-1] == s[0]:
        return s[1:-1]
    return s


def _normalize_capability(method_name: str) -> str:
    """Map a raw SDK method name onto the canonical capability kind."""
    lowered = method_name.lower()
    if "prompt" in lowered:
        return "prompt"
    if "resource" in lowered:
        return "resource"
    return "tool"


def _is_mcp_capability_decorator_set(decorator_types: Optional[List[str]]) -> bool:
    """Return True if any decorator names an MCP capability (`tool`/`prompt`/`resource`).

    Accepts the raw decorator strings recorded by Python AST extraction,
    which look like ``mcp.tool``, ``hello_mcp.prompt``, or just ``tool`` for
    bare decorators. The suffix after the last dot is the method name.
    """
    if not decorator_types:
        return False
    for dec in decorator_types:
        if not dec:
            continue
        bare = dec.rsplit(".", 1)[-1]
        # Drop any trailing call form, e.g. ``tool()`` -> ``tool``.
        bare = bare.split("(", 1)[0].strip().lower()
        if bare in _PY_MCP_CAPABILITY_TAGS:
            return True
    return False


def _is_same_ts_node(a, b) -> bool:
    """Compare tree-sitter nodes by their AST byte range.

    The tree-sitter Python binding can hand back fresh wrapper objects for
    the same underlying node, so plain ``is`` / ``==`` comparisons aren't
    reliable. Two nodes with the same ``start_byte`` and ``end_byte``
    occupy the same source span, which is enough for our purposes.
    """
    if a is None or b is None:
        return False
    return (
        a.start_byte == b.start_byte
        and a.end_byte == b.end_byte
        and a.type == b.type
    )


def _classify_mcp_annotation(annotations: List[str]) -> Optional[str]:
    """Return ``'tool'`` / ``'prompt'`` / ``'resource'`` if any annotation
    names an MCP capability; otherwise ``None``.

    Cross-language coverage:

    * Java/Spring AI:    ``@Tool``, ``@McpTool``
    * C# (.NET SDK):     ``[McpServerTool]``, ``[Tool]``
    * Rust (rmcp):       ``#[tool(...)]``, ``#[mcp::tool]``
    * PHP (php-mcp):     ``#[Tool(...)]``
    * Ruby (mcp-rb):     ``# @tool name: ...``
    """
    keywords = _PY_MCP_CAPABILITY_TAGS
    for ann in annotations or []:
        if not ann:
            continue
        for m in _MCP_ANNOTATION_RE.finditer(ann):
            ident = m.group(1).lower()
            for kw in keywords:
                if kw in ident:
                    return kw
    return None


def _parse_name_from_annotations(annotations: List[str]) -> Optional[str]:
    """Pull a ``name=...``/``name:...`` string argument out of annotations."""
    for ann in annotations or []:
        if not ann:
            continue
        m = _MCP_NAME_ARG_RE.search(ann)
        if m:
            return m.group(1)
    return None


@dataclass
class NativeAnalysisResult:
    """Result of native analysis for a single unit."""

    success: bool
    language: str
    functions: List[FunctionContext] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    partial: bool = False


class NativeAnalyzer:
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

    def extract_mcp_capability_contexts(self) -> List[FunctionContext]:
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
            all_funcs = self.extract_all_function_contexts()
            return [
                fc
                for fc in all_funcs
                if _is_mcp_capability_decorator_set(fc.decorator_types)
            ]

        if self.language not in self.FUNCTION_NODE_TYPES:
            return []

        lang_mod = _get_language_module(self.language)
        if lang_mod is None:
            return []

        try:
            if self.language == "typescript":
                lang = Language(lang_mod.language_typescript())
            elif self.language == "php":
                lang = Language(lang_mod.language_php())
            else:
                lang = Language(lang_mod.language())

            parser = Parser(lang)
            tree = parser.parse(self.source_bytes)
            imports = self._ts_extract_imports(tree.root_node)
        except Exception as e:
            self.logger.warning(
                f"MCP capability extraction failed for {self.file_path}: {e}"
            )
            return []

        func_types = self.FUNCTION_NODE_TYPES.get(self.language, set())
        contexts: List[FunctionContext] = []
        # Dedupe by handler start_byte so the same function definition can
        # only be returned once even when both passes locate it.
        seen_handlers: Set[int] = set()

        # -----------------------------------------------------------------
        # Pass 1: function-attached annotation/attribute/macro detection
        # -----------------------------------------------------------------
        def visit_funcs(node):
            if (
                node.type in func_types
                and node.type not in _TS_NON_FUNCTION_NODE_TYPES
            ):
                annotations = self._ts_collect_function_annotations(node)
                cap_kind = _classify_mcp_annotation(annotations)
                if (
                    cap_kind is not None
                    and node.start_byte not in seen_handlers
                ):
                    seen_handlers.add(node.start_byte)
                    self._append_capability_context(
                        contexts,
                        node,
                        imports,
                        capability=cap_kind,
                        registered_name=_parse_name_from_annotations(annotations),
                        source_kind="annotation",
                    )
            for child in node.children:
                visit_funcs(child)

        visit_funcs(tree.root_node)

        # -----------------------------------------------------------------
        # Pass 2: SDK call-site registration detection
        # -----------------------------------------------------------------
        registrations = self._ts_find_mcp_registrations(tree.root_node)
        for reg in registrations:
            handler_node = reg.get("handler_node")
            handler_name = reg.get("handler_name")

            if handler_node is None and handler_name:
                handler_node = self._ts_find_function_def_by_name(
                    tree.root_node, handler_name, func_types
                )
            if handler_node is None:
                continue
            if handler_node.start_byte in seen_handlers:
                continue
            seen_handlers.add(handler_node.start_byte)

            self._append_capability_context(
                contexts,
                handler_node,
                imports,
                capability=reg["capability"],
                registered_name=reg.get("name"),
                source_kind="registration",
            )

        return contexts

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

    def _ts_find_enclosing_class_name(self, node: "Node") -> str:
        """Walk up parents to find the nearest enclosing class-like name.

        Returns the class name (e.g. ``"CalcService"``) or ``""`` if the
        function is defined at module scope.
        """
        class_types = self.CLASS_NODE_TYPES.get(self.language, set())
        if not class_types:
            return ""

        cur = node.parent
        while cur is not None:
            if cur.type in class_types:
                name_node = cur.child_by_field_name("name")
                if name_node is not None:
                    return self._ts_get_node_text(name_node)
                # PHP's ``class_declaration`` exposes its name via a
                # ``name`` child without a field tag — fall back to text.
                for sub in cur.children:
                    if sub.type in ("name", "identifier", "type_identifier"):
                        return self._ts_get_node_text(sub)
                return ""
            cur = cur.parent
        return ""

    def _ts_collect_function_annotations(self, fn_node: "Node") -> List[str]:
        """Collect annotation/attribute/macro text strings on a function.

        Combines two extraction styles so we catch the patterns used across
        the supported languages:

        * **Sibling-based**: Rust ``attribute_item`` and Ruby ``comment``
          land as the function's previous sibling. Walk back through the
          siblings until we hit a "real" node.
        * **Nested**: Java's ``modifiers`` and C#/PHP's ``attribute_list``
          live *inside* the function/method node and wrap one or more
          ``annotation`` / ``marker_annotation`` / ``attribute`` children.
        """
        out: List[str] = []

        # (a) Sibling-based annotations / leading comments.
        sib = fn_node.prev_sibling
        steps = 0
        while sib is not None and steps < 8:
            kind = sib.type
            if kind in (
                "attribute_item",
                "decorator",
                "annotation",
                "marker_annotation",
            ):
                out.append(self._ts_get_node_text(sib))
            elif kind in ("comment", "line_comment", "block_comment"):
                out.append(self._ts_get_node_text(sib))
                # Comments don't chain — one leading comment is enough.
                break
            else:
                # Hit a real node — stop walking back.
                break
            sib = sib.prev_sibling
            steps += 1

        # (b) Nested annotations directly inside the function/method node.
        # We always preserve the WRAPPER text (which contains the sigil
        # like ``[`` / ``@``) AND drill into individual annotation/attribute
        # children. The wrapper text is what the regex classifier matches
        # against; the inner children are still useful for other consumers
        # such as ``_parse_name_from_annotations``.
        for child in fn_node.children:
            ctype = child.type
            if ctype in ("modifiers", "attribute_list", "decorator_list"):
                wrapper_text = self._ts_get_node_text(child)
                if any(sigil in wrapper_text for sigil in ("@", "[", "#[")):
                    out.append(wrapper_text)
                for sub in child.children:
                    if sub.type in (
                        "annotation",
                        "marker_annotation",
                        "attribute",
                        "decorator",
                    ):
                        out.append(self._ts_get_node_text(sub))

        return out

    def _ts_find_mcp_registrations(self, root: "Node") -> List[Dict[str, Any]]:
        """Find call expressions that look like MCP capability registrations.

        Returns a list of dicts describing each registration::

            {
                "capability": "tool" | "prompt" | "resource",
                "name": Optional[str],          # the registered MCP name
                "handler_node": Optional[Node], # inline arrow/function expr
                "handler_name": Optional[str],  # identifier ref otherwise
            }

        Walks with a parent pointer so we can recognize Kotlin-style
        trailing lambdas, which tree-sitter parses as a nested call
        expression where the *outer* call's function field is the *inner*
        ``server.addTool(...)`` call and the lambda is the outer call's
        sibling.
        """
        registrations: List[Dict[str, Any]] = []

        def visit(node: "Node", parent: Optional["Node"]):
            if node.type == "call_expression":
                method = self._ts_call_method_name(node)
                if method and method.lower() in _MCP_REGISTRATION_METHODS:
                    args_node = self._ts_call_arguments_node(node)
                    reg = self._ts_parse_registration_args(args_node, method.lower())
                    if reg is None:
                        # No string name and no inline/named handler in
                        # ``arguments``, but the call site itself still
                        # qualifies as a registration; allow Pass 1 (the
                        # trailing-lambda lookup below) to populate the
                        # handler.
                        reg = {
                            "capability": _normalize_capability(method.lower()),
                            "name": None,
                            "handler_node": None,
                            "handler_name": None,
                        }

                    # Kotlin: ``server.addTool(...) { req -> }`` parses as
                    # an OUTER call whose callee is the inner call we just
                    # matched, and whose other child is the
                    # ``annotated_lambda``. Kotlin's grammar exposes
                    # neither ``function`` nor ``arguments`` as fields, so
                    # we check structural position instead: are we the
                    # callee of the parent call? (i.e. the parent's first
                    # significant child is us).
                    if (
                        reg.get("handler_node") is None
                        and parent is not None
                        and parent.type == "call_expression"
                        and self._ts_is_callee_of_parent(node, parent)
                    ):
                        for sibling in parent.children:
                            if _is_same_ts_node(sibling, node):
                                continue
                            lambda_node = self._ts_unwrap_trailing_lambda(sibling)
                            if lambda_node is not None:
                                reg["handler_node"] = lambda_node
                                break

                    if reg.get("name") is None and args_node is not None:
                        reg["name"] = self._ts_first_string_literal_in_args(
                            args_node
                        )

                    if (
                        reg.get("handler_node") is not None
                        or reg.get("handler_name") is not None
                    ):
                        registrations.append(reg)
            for child in node.children:
                visit(child, node)

        visit(root, None)
        return registrations

    def _ts_call_method_name(self, call_node: "Node") -> Optional[str]:
        """Return the method name from a ``<expr>.method(...)`` call, or None.

        Tree-sitter grammars vary along two axes:

        * Whether the call expression exposes its callee via a named field
          (``function`` for JS/TS/Go, no field for Kotlin).
        * What node type holds the dotted access (``member_expression`` in
          JS/TS, ``selector_expression`` in Go, ``navigation_expression``
          in Kotlin) and how the right-hand identifier is exposed
          (``property`` field for JS/TS, ``field`` for Go, unnamed
          trailing ``identifier`` child for Kotlin).

        We probe field names first (the cheap, exact path) and fall back
        to scanning children-by-type so Kotlin's fieldless grammar still
        works.
        """
        func = call_node.child_by_field_name("function")
        if func is None:
            # Kotlin: ``call_expression`` has no ``function`` field; the
            # callee is the first non-trivia child, the ``value_arguments``
            # block is the second.
            for child in call_node.children:
                if child.type in (
                    "navigation_expression",
                    "member_expression",
                    "selector_expression",
                    "identifier",
                    "simple_identifier",
                    "scoped_identifier",
                    "field_access",
                    "method_invocation",
                ):
                    func = child
                    break
        if func is None:
            return None

        for field_name in ("property", "field", "name"):
            prop = func.child_by_field_name(field_name)
            if prop is not None:
                return self._ts_get_node_text(prop)

        if func.type in (
            "navigation_expression",
            "member_expression",
            "selector_expression",
        ):
            for child in reversed(func.children):
                if child.type in (
                    "identifier",
                    "simple_identifier",
                    "field_identifier",
                    "property_identifier",
                ):
                    return self._ts_get_node_text(child)
        return None

    def _ts_call_arguments_node(self, call_node: "Node") -> Optional["Node"]:
        """Return the call's argument list node, regardless of grammar shape.

        Most grammars expose the argument list under the ``arguments`` field
        (JS/TS/Go/Java). Kotlin doesn't — it has an unnamed
        ``value_arguments`` child instead. Fall back to a children-by-type
        scan so capability detection works there too.
        """
        named = call_node.child_by_field_name("arguments")
        if named is not None:
            return named
        for child in call_node.children:
            if child.type in (
                "arguments",
                "argument_list",
                "value_arguments",
            ):
                return child
        return None

    def _ts_is_callee_of_parent(
        self, node: "Node", parent: "Node"
    ) -> bool:
        """Return True if ``node`` is the callee position of ``parent``.

        Two-step check that supports both field-typed grammars (JS/TS/Go,
        which expose ``parent.function``) and field-less grammars (Kotlin,
        where the callee is just the parent call's first significant
        child).
        """
        named_func = parent.child_by_field_name("function")
        if named_func is not None and _is_same_ts_node(named_func, node):
            return True
        for child in parent.children:
            if child.is_named:
                return _is_same_ts_node(child, node)
        return False

    def _ts_unwrap_trailing_lambda(self, node: "Node") -> Optional["Node"]:
        """Return a lambda node from a Kotlin trailing-lambda position.

        Accepts either an ``annotated_lambda`` (which wraps a
        ``lambda_literal``) or a ``lambda_literal`` directly; anything else
        returns ``None`` so the caller can keep scanning siblings.
        """
        if node.type == "lambda_literal":
            return node
        if node.type == "annotated_lambda":
            for sub in node.children:
                if sub.type == "lambda_literal":
                    return sub
            return node
        return None

    def _ts_first_string_literal_in_args(
        self, args_node: "Node"
    ) -> Optional[str]:
        """Return the first string-literal value inside an arguments list.

        Used as a fallback after the structured parse misses (e.g. Kotlin's
        ``value_argument`` wrappers, or grammars that expose argument lists
        without the field shapes we expect).
        """
        for child in args_node.children:
            stripped = self._ts_extract_string_literal_text(child)
            if stripped is not None:
                return stripped
        return None

    def _ts_extract_string_literal_text(
        self, node: "Node"
    ) -> Optional[str]:
        """If ``node`` (or its single value child) is a string literal, return
        the unquoted text; otherwise ``None``.

        Kotlin's ``value_argument`` wraps the actual literal; Go's
        ``interpreted_string_literal`` contains string-content children
        between the quotes. We just take the node text and strip the outer
        matched quotes.
        """
        string_node_types = {
            "string",
            "string_literal",
            "template_string",
            "raw_string_literal",
            "interpreted_string_literal",
        }
        if node.type in string_node_types:
            return _strip_string_quotes(self._ts_get_node_text(node))
        if node.type == "value_argument":
            # Kotlin: the actual literal is the single non-trivia child
            for sub in node.children:
                if sub.type in string_node_types:
                    return _strip_string_quotes(self._ts_get_node_text(sub))
        return None

    def _ts_parse_registration_args(
        self, args_node: Optional["Node"], capability_method: str
    ) -> Optional[Dict[str, Any]]:
        """Pull the registered name + handler out of a registration call.

        Across SDKs the handler shows up in different argument positions:

        * JS/TS v1:  ``server.tool('name', schema, HANDLER)`` — handler is
          the inline arrow/function (last function-typed argument).
        * TS v2:    ``server.registerTool('name', config, HANDLER)`` — same.
        * Go:       ``mcp.AddTool(SERVER, &mcp.Tool{...}, HANDLER)`` — the
          handler is the LAST identifier; the first identifier (``server``)
          is the receiver and must not be confused with the handler.

        So we collect *all* candidate identifiers / inline functions /
        object-literal args during a single pass and then pick the most
        likely handler at the end (inline function wins; otherwise the
        last identifier that isn't the obvious "server" receiver wins).
        Object literals with a ``handler``/``execute``/``fn``/``callback``
        field are also honored.
        """
        if args_node is None:
            return None

        func_types = self.FUNCTION_NODE_TYPES.get(self.language, set())
        string_node_types = {
            "string",
            "string_literal",
            "template_string",
            "raw_string_literal",
            "interpreted_string_literal",
        }
        name: Optional[str] = None
        inline_handler: Optional["Node"] = None
        identifier_refs: List[str] = []

        for child in args_node.children:
            if child.type in ("(", ")", ",", "comment"):
                continue

            # Inline function expression / arrow function / lambda.
            if inline_handler is None and child.type in func_types:
                inline_handler = child
                continue

            # Bare identifier reference (resolved later against in-file defs).
            if child.type == "identifier":
                identifier_refs.append(self._ts_get_node_text(child))
                continue

            # First string literal we see is conventionally the MCP name
            # (e.g. ``'add'`` in ``server.tool('add', schema, handler)``).
            if name is None and child.type in string_node_types:
                name = _strip_string_quotes(self._ts_get_node_text(child))
                continue

            # Object/struct literal may carry ``{ name: '...', handler: fn }``
            # or Go's ``&mcp.Tool{Name: "add"}`` (which we read for the name
            # only — the handler is a separate positional arg in Go).
            if child.type in (
                "object",
                "object_expression",
                "literal_value",
                "composite_literal",
            ):
                obj_name, obj_handler = self._ts_extract_handler_from_object(
                    child, func_types
                )
                if name is None and obj_name:
                    name = obj_name
                if inline_handler is None and obj_handler is not None:
                    inline_handler = obj_handler
                continue

            # Unary/pointer wrapper around an object literal (Go
            # ``&mcp.Tool{...}``): peek through to find a Name field.
            if child.type == "unary_expression":
                for sub in child.children:
                    if sub.type in ("composite_literal", "literal_value"):
                        obj_name, _ = self._ts_extract_handler_from_object(
                            sub, func_types
                        )
                        if name is None and obj_name:
                            name = obj_name
                        break

        handler_node = inline_handler
        handler_name: Optional[str] = None

        if handler_node is None and identifier_refs:
            # Prefer the LAST identifier: in ``mcp.AddTool(server, ..., add)``
            # ``server`` is the receiver, ``add`` is the handler. The
            # inline-function check above already covers the JS/TS case
            # where the handler is the first inline argument.
            handler_name = identifier_refs[-1]

        if handler_node is None and handler_name is None:
            return None

        return {
            "capability": _normalize_capability(capability_method),
            "name": name,
            "handler_node": handler_node,
            "handler_name": handler_name,
        }

    def _ts_extract_handler_from_object(
        self, obj_node: "Node", func_types: Set[str]
    ) -> "tuple[Optional[str], Optional[Node]]":
        """Pull ``name`` + handler out of an object literal argument."""
        obj_name: Optional[str] = None
        obj_handler: Optional["Node"] = None

        # ``pair`` (JS), ``field_initialization`` (TS), ``key_value`` (Go),
        # ``element`` (Ruby) — try them all.
        pair_types = {
            "pair",
            "field_initialization",
            "key_value",
            "object_property",
            "element",
        }

        for child in obj_node.children:
            if child.type not in pair_types:
                continue
            key_node = child.child_by_field_name("key")
            value_node = child.child_by_field_name("value")
            if key_node is None or value_node is None:
                continue
            key = _strip_string_quotes(self._ts_get_node_text(key_node).strip())
            if (
                key == "name"
                and obj_name is None
                and value_node.type
                in (
                    "string",
                    "string_literal",
                    "template_string",
                    "raw_string_literal",
                    "interpreted_string_literal",
                )
            ):
                obj_name = _strip_string_quotes(self._ts_get_node_text(value_node))
            elif (
                key in ("handler", "execute", "fn", "callback", "run")
                and value_node.type in func_types
            ):
                obj_handler = value_node

        return obj_name, obj_handler

    def _ts_find_function_def_by_name(
        self, root: "Node", target_name: str, func_types: Set[str]
    ) -> Optional["Node"]:
        """Find a function/arrow-function definition by symbol name."""
        if not target_name:
            return None

        found: List["Node"] = []

        def visit(node: "Node"):
            if found:
                return
            if node.type in func_types:
                name_node = node.child_by_field_name("name")
                if (
                    name_node is not None
                    and self._ts_get_node_text(name_node) == target_name
                ):
                    found.append(node)
                    return
                # Arrow function assigned to a variable:
                #   const handler = async (args) => { ... };
                if (
                    node.type == "arrow_function"
                    and node.parent is not None
                    and node.parent.type == "variable_declarator"
                ):
                    parent_name = node.parent.child_by_field_name("name")
                    if (
                        parent_name is not None
                        and self._ts_get_node_text(parent_name) == target_name
                    ):
                        found.append(node)
                        return
            for child in node.children:
                if found:
                    return
                visit(child)

        visit(root)
        return found[0] if found else None

    # =========================================================================
    # Python Analysis - Pure AST extraction
    # =========================================================================

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

    def _py_extract_imports(self, tree: ast.AST) -> List[str]:
        """Extract all imports from Python AST."""
        imports = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    stmt = f"import {alias.name}"
                    if alias.asname:
                        stmt += f" as {alias.asname}"
                    imports.append(stmt)
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                for alias in node.names:
                    stmt = f"from {module} import {alias.name}"
                    if alias.asname:
                        stmt += f" as {alias.asname}"
                    imports.append(stmt)
        return imports

    def _py_extract_function(
        self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef], module_imports: List[str]
    ) -> FunctionContext:
        """Extract FunctionContext from Python function AST node with full dataflow analysis.
        
        Uses the existing ForwardDataflowAnalysis infrastructure for proper
        CFG-based taint tracking with shape-aware analysis.
        """
        name = node.name
        docstring = ast.get_docstring(node)
        line_number = node.lineno

        # Extract decorators from AST
        decorator_types = []
        decorator_params: Dict[str, Dict[str, Any]] = {}
        for dec in node.decorator_list:
            dec_name = self._py_get_node_name(dec)
            decorator_types.append(dec_name)
            if isinstance(dec, ast.Call):
                dec_params = self._py_extract_call_kwargs(dec)
                if dec_params:
                    decorator_params[dec_name] = dec_params

        # Extract parameters from AST
        parameters = []
        param_names = []
        for arg in node.args.args:
            param_info: Dict[str, Any] = {"name": arg.arg}
            if arg.annotation:
                param_info["type"] = self._py_unparse_safe(arg.annotation)
            parameters.append(param_info)
            param_names.append(arg.arg)

        # Extract return type from AST
        return_type = self._py_unparse_safe(node.returns) if node.returns else None
        
        # Use existing ForwardDataflowAnalysis for proper CFG-based taint tracking
        parameter_flows = self._py_analyze_dataflow_full(node, param_names)
        
        # Detect security operations via dataflow
        security_ops = self._py_detect_security_ops(node)

        # Extract ALL function calls from AST
        function_calls = []
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                function_calls.append({
                    "name": self._py_get_node_name(child.func),
                    "args": [self._py_unparse_safe(a) for a in child.args],
                    "kwargs": {kw.arg: self._py_unparse_safe(kw.value) for kw in child.keywords if kw.arg},
                    "line": getattr(child, "lineno", 0),
                })

        # Extract ALL assignments from AST
        assignments = []
        for child in ast.walk(node):
            if isinstance(child, ast.Assign):
                for target in child.targets:
                    assignments.append({
                        "target": self._py_unparse_safe(target),
                        "value": self._py_unparse_safe(child.value),
                        "line": getattr(child, "lineno", 0),
                    })
            elif isinstance(child, ast.AnnAssign):
                assignments.append({
                    "target": self._py_unparse_safe(child.target),
                    "annotation": self._py_unparse_safe(child.annotation),
                    "value": self._py_unparse_safe(child.value) if child.value else None,
                    "line": getattr(child, "lineno", 0),
                })
            elif isinstance(child, ast.AugAssign):
                assignments.append({
                    "target": self._py_unparse_safe(child.target),
                    "op": child.op.__class__.__name__,
                    "value": self._py_unparse_safe(child.value),
                    "line": getattr(child, "lineno", 0),
                })

        # Extract control flow from AST
        control_flow = {
            "if_statements": [{"line": n.lineno, "test": self._py_unparse_safe(n.test)}
                             for n in ast.walk(node) if isinstance(n, ast.If)],
            "for_loops": [{"line": n.lineno, "target": self._py_unparse_safe(n.target),
                          "iter": self._py_unparse_safe(n.iter)}
                         for n in ast.walk(node) if isinstance(n, (ast.For, ast.AsyncFor))],
            "while_loops": [{"line": n.lineno, "test": self._py_unparse_safe(n.test)}
                           for n in ast.walk(node) if isinstance(n, ast.While)],
            "try_blocks": [{"line": n.lineno} for n in ast.walk(node) if isinstance(n, ast.Try)],
            "with_statements": [{"line": n.lineno, "items": [self._py_unparse_safe(i.context_expr) for i in n.items]}
                               for n in ast.walk(node) if isinstance(n, (ast.With, ast.AsyncWith))],
        }

        # Extract ALL constants from AST
        constants: Dict[str, Any] = {}
        for child in ast.walk(node):
            if isinstance(child, ast.Assign):
                for target in child.targets:
                    if isinstance(target, ast.Name) and isinstance(child.value, ast.Constant):
                        constants[target.id] = child.value.value

        # Extract variable dependencies from AST
        var_deps: Dict[str, List[str]] = {}
        for child in ast.walk(node):
            if isinstance(child, ast.Assign):
                for target in child.targets:
                    if isinstance(target, ast.Name):
                        deps = [n.id for n in ast.walk(child.value) if isinstance(n, ast.Name)]
                        var_deps[target.id] = deps

        # Extract ALL string literals from AST
        string_literals = []
        for child in ast.walk(node):
            if isinstance(child, ast.Constant) and isinstance(child.value, str):
                if child.value and len(child.value) <= 500:
                    string_literals.append(child.value)
        string_literals = list(set(string_literals))[:50]

        # Extract ALL return expressions from AST
        return_expressions = []
        for child in ast.walk(node):
            if isinstance(child, ast.Return) and child.value:
                return_expressions.append(self._py_unparse_safe(child.value))

        # Extract exception handlers from AST
        exception_handlers = []
        for child in ast.walk(node):
            if isinstance(child, ast.ExceptHandler):
                exception_handlers.append({
                    "line": child.lineno,
                    "type": self._py_unparse_safe(child.type) if child.type else "Exception",
                    "name": child.name,
                    "body_size": len(child.body),
                })

        # Extract global/nonlocal from AST
        global_writes = []
        for child in ast.walk(node):
            if isinstance(child, ast.Global):
                for name in child.names:
                    global_writes.append({"type": "global", "name": name, "line": child.lineno})
            elif isinstance(child, ast.Nonlocal):
                for name in child.names:
                    global_writes.append({"type": "nonlocal", "name": name, "line": child.lineno})

        # Extract attribute access from AST
        attribute_access = []
        for child in ast.walk(node):
            if isinstance(child, ast.Attribute):
                attribute_access.append({
                    "object": self._py_unparse_safe(child.value),
                    "attr": child.attr,
                    "line": getattr(child, "lineno", 0),
                })
        attribute_access = attribute_access[:50]

        # Extract subscript access from AST
        subscript_access = []
        for child in ast.walk(node):
            if isinstance(child, ast.Subscript):
                subscript_access.append({
                    "value": self._py_unparse_safe(child.value),
                    "slice": self._py_unparse_safe(child.slice),
                    "line": getattr(child, "lineno", 0),
                })

        # Calculate complexity from AST
        complexity = 1
        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.For, ast.While, ast.ExceptHandler, ast.With)):
                complexity += 1
            elif isinstance(child, ast.BoolOp):
                complexity += len(child.values) - 1

        # Build dataflow summary with taint info
        dataflow_summary = {
            "total_statements": len([n for n in ast.walk(node) if isinstance(n, ast.stmt)]),
            "total_expressions": len([n for n in ast.walk(node) if isinstance(n, ast.expr)]),
            "complexity": complexity,
            "subscript_access": subscript_access[:20],
            "param_flows": {p["parameter_name"]: {
                "reaches_calls": p.get("reaches_calls", []),
                "reaches_returns": p.get("reaches_returns", False),
                "reaches_external": p.get("reaches_external", False),
            } for p in parameter_flows},
        }

        # Build FunctionContext with dataflow analysis results
        return FunctionContext(
            name=name,
            decorator_types=decorator_types,
            decorator_params=decorator_params,
            docstring=docstring,
            parameters=parameters,
            return_type=return_type,
            line_number=line_number,
            imports=module_imports,
            function_calls=function_calls,
            assignments=assignments,
            control_flow=control_flow,
            parameter_flows=parameter_flows,  # Already list of dicts
            constants=constants,
            variable_dependencies=var_deps,
            has_file_operations=security_ops["has_file_operations"],
            has_network_operations=security_ops["has_network_operations"],
            has_subprocess_calls=security_ops["has_subprocess_calls"],
            has_eval_exec=security_ops["has_eval_exec"],
            has_dangerous_imports=any(d in " ".join(module_imports) for d in ["subprocess", "os", "pickle", "marshal"]),
            dataflow_summary=dataflow_summary,
            string_literals=string_literals,
            return_expressions=return_expressions,
            exception_handlers=exception_handlers,
            env_var_access=[],
            global_writes=global_writes,
            attribute_access=attribute_access,
        )

    def _py_get_node_name(self, node: ast.expr) -> str:
        """Get name from any AST expression node."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            parts = []
            current: ast.expr = node
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts))
        elif isinstance(node, ast.Call):
            return self._py_get_node_name(node.func)
        else:
            return self._py_unparse_safe(node)

    def _py_extract_call_kwargs(self, call: ast.Call) -> Dict[str, Any]:
        """Extract keyword arguments from a call node."""
        kwargs: Dict[str, Any] = {}
        for kw in call.keywords:
            if kw.arg:
                kwargs[kw.arg] = self._py_unparse_safe(kw.value)
        return kwargs

    def _py_unparse_safe(self, node: Optional[ast.AST]) -> str:
        """Safely unparse an AST node to string."""
        if node is None:
            return ""
        try:
            return ast.unparse(node)
        except Exception:
            return f"<{node.__class__.__name__}>"

    def _py_analyze_dataflow_full(
        self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef], param_names: List[str]
    ) -> List[Dict[str, Any]]:
        """Perform full dataflow analysis using existing ForwardDataflowAnalysis.
        
        This leverages the CFG-based taint tracking infrastructure from
        mcpscanner.core.static_analysis.dataflow and taint modules.
        """
        try:
            # Create a function-specific source for the parser
            func_source = ast.unparse(node)
            func_parser = PythonParser(func_source)
            func_parser.parse()
            
            # Use ForwardDataflowAnalysis for proper CFG-based analysis
            tracker = ForwardDataflowAnalysis(func_parser, param_names)
            flows = tracker.analyze_forward_flows()
            
            # Convert FlowPath objects to dicts for FunctionContext
            return [{
                "parameter_name": flow.parameter_name,
                "operations": flow.operations,
                "reaches_calls": flow.reaches_calls,
                "reaches_assignments": flow.reaches_assignments,
                "reaches_returns": flow.reaches_returns,
                "reaches_external": flow.reaches_external,
            } for flow in flows]
        except Exception as e:
            self.logger.debug(f"Full dataflow analysis failed, using simple analysis: {e}")
            # Fallback to simple analysis
            return self._py_analyze_dataflow_simple(node, param_names)

    def _py_analyze_dataflow_simple(
        self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef], param_names: List[str]
    ) -> List[Dict[str, Any]]:
        """Simple dataflow analysis fallback when full analysis fails."""
        # Reset taint environment
        self._taint_env = {}
        for pname in param_names:
            self._taint_env[pname] = TaintInfo(status=TaintStatus.TAINTED, sources={pname})
        
        flows = {name: {"parameter_name": name, "operations": [], "reaches_calls": [], 
                       "reaches_assignments": [], "reaches_returns": False, "reaches_external": False} 
                for name in param_names}
        
        external_patterns = {"open", "read", "write", "requests", "urllib", "subprocess", "os.system", "eval", "exec"}
        
        for child in ast.walk(node):
            if isinstance(child, ast.Assign):
                rhs_taint = self._py_eval_taint(child.value)
                for target in child.targets:
                    if isinstance(target, ast.Name):
                        self._taint_env[target.id] = rhs_taint
                        if rhs_taint.is_tainted():
                            for param in param_names:
                                if param in rhs_taint.sources:
                                    flows[param]["reaches_assignments"].append(target.id)
            
            elif isinstance(child, ast.Call):
                call_name = self._py_get_node_name(child.func)
                for arg in child.args:
                    arg_taint = self._py_eval_taint(arg)
                    if arg_taint.is_tainted():
                        for param in param_names:
                            if param in arg_taint.sources:
                                flows[param]["reaches_calls"].append(call_name)
                                if any(p in call_name for p in external_patterns):
                                    flows[param]["reaches_external"] = True
            
            elif isinstance(child, ast.Return) and child.value:
                ret_taint = self._py_eval_taint(child.value)
                if ret_taint.is_tainted():
                    for param in param_names:
                        if param in ret_taint.sources:
                            flows[param]["reaches_returns"] = True
        
        return list(flows.values())

    def _py_eval_taint(self, expr: ast.AST) -> TaintInfo:
        """Evaluate taint of a Python expression."""
        if isinstance(expr, ast.Name):
            return self._taint_env.get(expr.id, TaintInfo())
        elif isinstance(expr, ast.Attribute):
            return self._py_eval_taint(expr.value)
        elif isinstance(expr, ast.Subscript):
            return self._py_eval_taint(expr.value)
        elif isinstance(expr, ast.Call):
            result = TaintInfo()
            for arg in expr.args:
                result = result.merge(self._py_eval_taint(arg))
            for kw in expr.keywords:
                result = result.merge(self._py_eval_taint(kw.value))
            return result
        elif isinstance(expr, ast.BinOp):
            left = self._py_eval_taint(expr.left)
            right = self._py_eval_taint(expr.right)
            return left.merge(right)
        elif isinstance(expr, ast.JoinedStr):
            result = TaintInfo()
            for value in expr.values:
                if isinstance(value, ast.FormattedValue):
                    result = result.merge(self._py_eval_taint(value.value))
            return result
        elif isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
            result = TaintInfo()
            for elt in expr.elts:
                result = result.merge(self._py_eval_taint(elt))
            return result
        elif isinstance(expr, ast.Dict):
            result = TaintInfo()
            for v in expr.values:
                if v:
                    result = result.merge(self._py_eval_taint(v))
            return result
        return TaintInfo()

    def _py_detect_security_ops(self, node: ast.AST) -> Dict[str, bool]:
        """Detect security-relevant operations via dataflow analysis."""
        has_file = False
        has_network = False
        has_subprocess = False
        has_eval = False
        
        file_patterns = {"open", "read", "write", "close", "os.remove", "os.unlink", "shutil", "pathlib"}
        network_patterns = {"requests", "urllib", "http", "httpx", "aiohttp", "socket"}
        subprocess_patterns = {"subprocess", "os.system", "os.popen", "os.exec"}
        eval_patterns = {"eval", "exec", "compile", "__import__"}
        
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                call_name = self._py_get_node_name(child.func)
                
                if any(p in call_name for p in file_patterns):
                    has_file = True
                if any(p in call_name for p in network_patterns):
                    has_network = True
                if any(p in call_name for p in subprocess_patterns):
                    has_subprocess = True
                if call_name in eval_patterns:
                    has_eval = True
        
        return {
            "has_file_operations": has_file,
            "has_network_operations": has_network,
            "has_subprocess_calls": has_subprocess,
            "has_eval_exec": has_eval,
        }

    # =========================================================================
    # Generic Tree-sitter Analysis - Supports all non-Python languages
    # =========================================================================

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

    def _ts_extract_imports(self, root: "Node") -> List[str]:
        """Extract all imports from tree-sitter AST."""
        imports = []

        def visit(node: "Node"):
            # ES6 imports
            if node.type == "import_statement":
                imports.append(self._ts_get_node_text(node))
            # CommonJS require
            elif node.type == "call_expression":
                func = node.child_by_field_name("function")
                if func and self._ts_get_node_text(func) == "require":
                    imports.append(self._ts_get_node_text(node))
            for child in node.children:
                visit(child)

        visit(root)
        return imports

    def _ts_extract_functions(
        self, node: "Node", imports: List[str], functions: List[FunctionContext], class_name: str = ""
    ):
        """Recursively extract all functions from tree-sitter AST."""
        # Get function types for this language
        func_types = self.FUNCTION_NODE_TYPES.get(self.language, set())
        class_types = self.CLASS_NODE_TYPES.get(self.language, set())

        if node.type in func_types:
            try:
                ctx = self._ts_extract_function_context(node, imports, class_name)
                if ctx:
                    functions.append(ctx)
            except Exception as e:
                self.logger.warning(f"Failed to extract function: {e}")

        # Track class context
        current_class = class_name
        if node.type in class_types:
            name_node = node.child_by_field_name("name")
            if name_node:
                current_class = self._ts_get_node_text(name_node)

        # Recurse
        for child in node.children:
            self._ts_extract_functions(child, imports, functions, current_class)

    def _ts_extract_function_context(
        self, node: "Node", imports: List[str], class_name: str
    ) -> Optional[FunctionContext]:
        """Extract FunctionContext from tree-sitter function node with dataflow."""
        # Reset taint environment for this function
        self._taint_env = {}
        
        # Get function name
        name = self._ts_get_function_name(node)
        if class_name:
            name = f"{class_name}.{name}"

        # Get line number
        line_number = node.start_point[0] + 1

        # Extract parameters from AST and initialize taint tracking
        parameters = self._ts_extract_parameters(node)
        param_names = [p.get("name", "") for p in parameters if p.get("name")]
        for pname in param_names:
            self._taint_env[pname] = TaintInfo(status=TaintStatus.TAINTED, sources={pname})

        # Extract return type from AST (TypeScript)
        return_type = self._ts_extract_return_type(node)

        # Extract docstring/JSDoc from AST
        docstring = self._ts_extract_docstring(node)

        # Extract decorators from AST (TypeScript)
        decorator_types = self._ts_extract_decorators(node)

        # Extract ALL function calls from AST
        function_calls = self._ts_extract_calls(node)

        # Extract ALL assignments from AST
        assignments = self._ts_extract_assignments(node)

        # Extract control flow from AST
        control_flow = self._ts_extract_control_flow(node)

        # Extract ALL string literals from AST
        string_literals = self._ts_extract_strings(node)

        # Extract return expressions from AST
        return_expressions = self._ts_extract_returns(node)

        # Extract exception handlers from AST
        exception_handlers = self._ts_extract_catch_clauses(node)

        # Extract variable declarations from AST
        constants = self._ts_extract_constants(node)

        # Calculate complexity from AST
        complexity = self._ts_calculate_complexity(node)
        
        # Perform full CFG-based dataflow analysis
        parameter_flows = self._ts_analyze_dataflow_full(node, param_names)
        
        # Detect security operations
        security_ops = self._ts_detect_security_ops(node)
        
        # Extract raw context for LLM to parse tool descriptions
        raw_context = self._ts_extract_raw_context(node)
        
        # Build dataflow summary with raw context for LLM
        dataflow_summary = {
            "complexity": complexity,
            "param_flows": {p["parameter_name"]: {
                "reaches_calls": p.get("reaches_calls", []),
                "reaches_returns": p.get("reaches_returns", False),
                "reaches_external": p.get("reaches_external", False),
            } for p in parameter_flows},
            # Include raw context so LLM can parse tool descriptions
            "raw_decorator_context": raw_context,
        }

        return FunctionContext(
            name=name,
            decorator_types=decorator_types,
            decorator_params={},  # Empty - LLM will parse from raw_decorator_context
            docstring=docstring,
            parameters=parameters,
            return_type=return_type,
            line_number=line_number,
            imports=imports,
            function_calls=function_calls,
            assignments=assignments,
            control_flow=control_flow,
            parameter_flows=parameter_flows,  # Already list of dicts
            constants=constants,
            variable_dependencies={},
            has_file_operations=security_ops["has_file_operations"],
            has_network_operations=security_ops["has_network_operations"],
            has_subprocess_calls=security_ops["has_subprocess_calls"],
            has_eval_exec=security_ops["has_eval_exec"],
            has_dangerous_imports=False,
            dataflow_summary=dataflow_summary,
            string_literals=string_literals,
            return_expressions=return_expressions,
            exception_handlers=exception_handlers,
            env_var_access=[],
            global_writes=[],
            attribute_access=[],
        )

    def _ts_get_node_text(self, node: "Node") -> str:
        """Get text content of a tree-sitter node."""
        return self.source_bytes[node.start_byte:node.end_byte].decode("utf-8")

    def _ts_get_function_name(self, node: "Node") -> str:
        """Extract function name from tree-sitter node."""
        # Try name field
        name_node = node.child_by_field_name("name")
        if name_node:
            return self._ts_get_node_text(name_node)

        # For arrow functions assigned to variables, look at parent
        if node.type == "arrow_function" and node.parent:
            if node.parent.type == "variable_declarator":
                name_node = node.parent.child_by_field_name("name")
                if name_node:
                    return self._ts_get_node_text(name_node)

        return "<anonymous>"

    def _ts_extract_parameters(self, node: "Node") -> List[Dict[str, Any]]:
        """Extract parameters from tree-sitter function node."""
        params = []
        params_node = node.child_by_field_name("parameters")
        if not params_node:
            # Try various parameter list names
            for child in node.children:
                if child.type in ("formal_parameters", "parameters", "parameter_list"):
                    params_node = child
                    break

        if params_node:
            for child in params_node.children:
                param_info: Dict[str, Any] = {}
                
                # Handle different parameter node types across languages
                if child.type == "identifier":
                    # Simple identifier (JS/TS)
                    param_info["name"] = self._ts_get_node_text(child)
                
                elif child.type in ("required_parameter", "optional_parameter", "rest_parameter"):
                    # TypeScript parameters
                    name_node = child.child_by_field_name("pattern") or child.child_by_field_name("name")
                    if name_node:
                        param_info["name"] = self._ts_get_node_text(name_node)
                    type_node = child.child_by_field_name("type")
                    if type_node:
                        param_info["type"] = self._ts_get_node_text(type_node)
                
                elif child.type == "parameter_declaration":
                    # Go parameters
                    for subchild in child.children:
                        if subchild.type == "identifier":
                            param_info["name"] = self._ts_get_node_text(subchild)
                            break
                    # Get type (last non-identifier child)
                    for subchild in reversed(child.children):
                        if subchild.type not in ("identifier", ","):
                            param_info["type"] = self._ts_get_node_text(subchild)
                            break
                
                elif child.type == "formal_parameter":
                    # Java/Kotlin parameters
                    name_node = child.child_by_field_name("name")
                    type_node = child.child_by_field_name("type")
                    if name_node:
                        param_info["name"] = self._ts_get_node_text(name_node)
                    if type_node:
                        param_info["type"] = self._ts_get_node_text(type_node)
                
                elif child.type == "simple_parameter":
                    # Ruby parameters
                    param_info["name"] = self._ts_get_node_text(child)
                
                elif child.type == "parameter":
                    # Rust/PHP/Swift parameters
                    name_node = child.child_by_field_name("pattern") or child.child_by_field_name("name")
                    if name_node:
                        param_info["name"] = self._ts_get_node_text(name_node)
                    type_node = child.child_by_field_name("type")
                    if type_node:
                        param_info["type"] = self._ts_get_node_text(type_node)
                
                if param_info.get("name"):
                    params.append(param_info)
        
        return params

    def _ts_extract_return_type(self, node: "Node") -> Optional[str]:
        """Extract return type annotation from tree-sitter node."""
        return_type = node.child_by_field_name("return_type")
        if return_type:
            return self._ts_get_node_text(return_type)
        return None

    def _ts_extract_docstring(self, node: "Node") -> Optional[str]:
        """Extract JSDoc/doc comment from tree-sitter node.
        
        Captures comments that may contain tool descriptions for LLM analysis.
        """
        # Look for comment before function (JSDoc, block comment, etc.)
        if node.prev_sibling:
            sib = node.prev_sibling
            if sib.type in ("comment", "block_comment", "line_comment"):
                text = self._ts_get_node_text(sib)
                return text
        
        # Look for doc comment inside function (Go, Rust style)
        for child in node.children:
            if child.type in ("comment", "block_comment"):
                text = self._ts_get_node_text(child)
                return text
        
        return None

    def _ts_extract_decorators(self, node: "Node") -> List[str]:
        """Extract decorators/attributes from tree-sitter node.
        
        Captures full decorator text including arguments so LLM can parse
        tool descriptions like @tool(description="...") or #[tool(desc = "...")]
        """
        decorators = []
        
        # Check preceding siblings for decorators (TypeScript/Python style)
        sib = node.prev_sibling
        while sib:
            if sib.type in ("decorator", "attribute", "annotation"):
                decorators.append(self._ts_get_node_text(sib))
            elif sib.type == "comment":
                # Stop at comments (they're handled separately)
                break
            sib = sib.prev_sibling
        
        # Check children for decorators (some grammars nest them)
        for child in node.children:
            if child.type in ("decorator", "attribute", "annotation", "decorator_list"):
                if child.type == "decorator_list":
                    for dec in child.children:
                        decorators.append(self._ts_get_node_text(dec))
                else:
                    decorators.append(self._ts_get_node_text(child))
        
        # Reverse to get original order
        decorators.reverse()
        return decorators
    
    def _ts_extract_raw_context(self, node: "Node") -> str:
        """Extract raw context around function for LLM to parse tool descriptions.
        
        Captures surrounding code context so LLM can figure out tool descriptions
        from any pattern (decorators, call arguments, comments, etc.)
        """
        lines = self.source_bytes.decode("utf-8").split("\n")
        
        # For arrow functions/callbacks, find the parent call expression
        # This captures patterns like: server.registerTool('name', { description: '...' }, async () => {})
        parent_start = node.start_point[0]
        parent = node.parent
        while parent:
            if parent.type in ("call_expression", "expression_statement", "variable_declaration"):
                parent_start = parent.start_point[0]
                break
            parent = parent.parent
        
        # Get context: from parent start (or 10 lines before) to function start + 1
        start_line = max(0, min(parent_start, node.start_point[0] - 10))
        end_line = min(len(lines), node.start_point[0] + 2)
        
        context_lines = []
        for i in range(start_line, end_line):
            if i < len(lines):
                context_lines.append(lines[i])
        
        return "\n".join(context_lines)

    def _ts_extract_calls(self, node: "Node") -> List[Dict[str, Any]]:
        """Extract ALL function calls from tree-sitter AST."""
        calls = []

        def visit(n: "Node"):
            if n.type == "call_expression":
                func = n.child_by_field_name("function")
                args = n.child_by_field_name("arguments")
                calls.append({
                    "name": self._ts_get_node_text(func) if func else "<unknown>",
                    "args": self._ts_get_node_text(args) if args else "()",
                    "line": n.start_point[0] + 1,
                })
            for child in n.children:
                visit(child)

        visit(node)
        return calls

    def _ts_extract_assignments(self, node: "Node") -> List[Dict[str, Any]]:
        """Extract ALL assignments from tree-sitter AST."""
        assignments = []

        def visit(n: "Node"):
            if n.type == "assignment_expression":
                left = n.child_by_field_name("left")
                right = n.child_by_field_name("right")
                assignments.append({
                    "target": self._ts_get_node_text(left) if left else "",
                    "value": self._ts_get_node_text(right) if right else "",
                    "line": n.start_point[0] + 1,
                })
            elif n.type == "variable_declarator":
                name = n.child_by_field_name("name")
                value = n.child_by_field_name("value")
                if name:
                    assignments.append({
                        "target": self._ts_get_node_text(name),
                        "value": self._ts_get_node_text(value) if value else None,
                        "line": n.start_point[0] + 1,
                    })
            for child in n.children:
                visit(child)

        visit(node)
        return assignments

    def _ts_extract_control_flow(self, node: "Node") -> Dict[str, Any]:
        """Extract control flow from tree-sitter AST."""
        control_flow: Dict[str, List[Dict[str, Any]]] = {
            "if_statements": [],
            "for_loops": [],
            "while_loops": [],
            "try_blocks": [],
            "switch_statements": [],
        }

        def visit(n: "Node"):
            if n.type == "if_statement":
                cond = n.child_by_field_name("condition")
                control_flow["if_statements"].append({
                    "line": n.start_point[0] + 1,
                    "condition": self._ts_get_node_text(cond) if cond else "",
                })
            elif n.type in ("for_statement", "for_in_statement"):
                control_flow["for_loops"].append({
                    "line": n.start_point[0] + 1,
                    "header": self._ts_get_node_text(n)[:100],
                })
            elif n.type == "while_statement":
                cond = n.child_by_field_name("condition")
                control_flow["while_loops"].append({
                    "line": n.start_point[0] + 1,
                    "condition": self._ts_get_node_text(cond) if cond else "",
                })
            elif n.type == "try_statement":
                control_flow["try_blocks"].append({"line": n.start_point[0] + 1})
            elif n.type == "switch_statement":
                control_flow["switch_statements"].append({"line": n.start_point[0] + 1})
            for child in n.children:
                visit(child)

        visit(node)
        return control_flow

    def _ts_extract_strings(self, node: "Node") -> List[str]:
        """Extract ALL string literals from tree-sitter AST."""
        strings = []

        def visit(n: "Node"):
            if n.type in ("string", "template_string"):
                text = self._ts_get_node_text(n)
                if text and len(text) <= 500:
                    strings.append(text)
            for child in n.children:
                visit(child)

        visit(node)
        return list(set(strings))[:50]

    def _ts_extract_returns(self, node: "Node") -> List[str]:
        """Extract return expressions from tree-sitter AST."""
        returns = []

        def visit(n: "Node"):
            if n.type == "return_statement":
                # Get the expression after 'return'
                for child in n.children:
                    if child.type not in ("return", ";"):
                        returns.append(self._ts_get_node_text(child))
                        break
            for child in n.children:
                visit(child)

        visit(node)
        return returns

    def _ts_extract_catch_clauses(self, node: "Node") -> List[Dict[str, Any]]:
        """Extract catch clauses from tree-sitter AST."""
        handlers = []

        def visit(n: "Node"):
            if n.type == "catch_clause":
                param = n.child_by_field_name("parameter")
                handlers.append({
                    "line": n.start_point[0] + 1,
                    "parameter": self._ts_get_node_text(param) if param else None,
                })
            for child in n.children:
                visit(child)

        visit(node)
        return handlers

    def _ts_extract_constants(self, node: "Node") -> Dict[str, Any]:
        """Extract constants from tree-sitter AST."""
        constants: Dict[str, Any] = {}

        def visit(n: "Node"):
            if n.type == "variable_declarator":
                name = n.child_by_field_name("name")
                value = n.child_by_field_name("value")
                if name and value and value.type in ("number", "string", "true", "false", "null"):
                    constants[self._ts_get_node_text(name)] = self._ts_get_node_text(value)
            for child in n.children:
                visit(child)

        visit(node)
        return constants

    def _ts_calculate_complexity(self, node: "Node") -> int:
        """Calculate cyclomatic complexity from tree-sitter AST."""
        complexity = 1
        branch_types = {
            "if_statement", "for_statement", "for_in_statement", "while_statement",
            "do_statement", "switch_case", "catch_clause", "ternary_expression",
            "binary_expression",  # for && and ||
        }

        def visit(n: "Node"):
            nonlocal complexity
            if n.type in branch_types:
                if n.type == "binary_expression":
                    op = n.child_by_field_name("operator")
                    if op and self._ts_get_node_text(op) in ("&&", "||"):
                        complexity += 1
                else:
                    complexity += 1
            for child in n.children:
                visit(child)

        visit(node)
        return complexity

    def _ts_analyze_dataflow_full(self, node: "Node", param_names: List[str]) -> List[Dict[str, Any]]:
        """Perform full CFG-based dataflow analysis using TreeSitterDataflowAnalysis.
        
        This leverages the CFG builder and dataflow infrastructure to provide
        the same level of analysis as Python's ForwardDataflowAnalysis.
        """
        try:
            # Use full CFG-based dataflow analysis
            analyzer = TreeSitterDataflowAnalysis(
                language=self.language,
                function_node=node,
                param_names=param_names,
                source_bytes=self.source_bytes,
            )
            flows = analyzer.analyze()
            
            # Convert TSFlowPath objects to dicts
            return [flow.to_dict() for flow in flows]
        except Exception as e:
            self.logger.debug(f"Full tree-sitter dataflow analysis failed, using simple: {e}")
            # Fallback to simple analysis
            return self._ts_analyze_dataflow_simple(node, param_names)

    def _ts_analyze_dataflow_simple(self, node: "Node", param_names: List[str]) -> List[Dict[str, Any]]:
        """Simple fallback dataflow analysis when full analysis fails."""
        # Reset taint environment
        self._taint_env = {}
        for pname in param_names:
            self._taint_env[pname] = TaintInfo(status=TaintStatus.TAINTED, sources={pname})
        
        flows = {name: {"parameter_name": name, "operations": [], "reaches_calls": [],
                       "reaches_assignments": [], "reaches_returns": False, "reaches_external": False}
                for name in param_names}
        
        external_patterns = {"open", "read", "write", "fetch", "exec", "spawn", "system", "eval"}
        
        def visit(n: "Node"):
            if n.type in ("assignment_expression", "variable_declarator", "short_var_declaration"):
                target = n.child_by_field_name("left") or n.child_by_field_name("name")
                value = n.child_by_field_name("right") or n.child_by_field_name("value")
                
                if target and value:
                    target_name = self._ts_get_node_text(target)
                    taint = self._ts_eval_taint(value, param_names)
                    if target_name:
                        self._taint_env[target_name] = taint
                    if taint.is_tainted():
                        for param in param_names:
                            if param in taint.sources:
                                flows[param]["reaches_assignments"].append(target_name)
            
            elif n.type in ("call_expression", "new_expression", "method_invocation"):
                func = n.child_by_field_name("function") or n.child_by_field_name("name")
                args = n.child_by_field_name("arguments")
                if func and args:
                    call_name = self._ts_get_node_text(func)
                    args_taint = self._ts_eval_taint(args, param_names)
                    if args_taint.is_tainted():
                        for param in param_names:
                            if param in args_taint.sources:
                                flows[param]["reaches_calls"].append(call_name)
                                if any(p in call_name for p in external_patterns):
                                    flows[param]["reaches_external"] = True
            
            elif n.type == "return_statement":
                for child in n.children:
                    if child.type not in ("return", ";", "keyword"):
                        ret_taint = self._ts_eval_taint(child, param_names)
                        if ret_taint.is_tainted():
                            for param in param_names:
                                if param in ret_taint.sources:
                                    flows[param]["reaches_returns"] = True
                        break
            
            for child in n.children:
                visit(child)
        
        visit(node)
        return list(flows.values())

    def _ts_eval_taint(self, node: "Node", param_names: List[str]) -> TaintInfo:
        """Evaluate taint of tree-sitter expression via AST traversal."""
        result = TaintInfo()
        
        def visit(n: "Node") -> TaintInfo:
            """Recursively evaluate taint of AST node."""
            node_taint = TaintInfo()
            
            # Check if this is an identifier
            if n.type == "identifier":
                var_name = self._ts_get_node_text(n)
                # Direct parameter reference
                if var_name in param_names:
                    node_taint = TaintInfo(status=TaintStatus.TAINTED, sources={var_name})
                # Variable in taint environment
                elif var_name in self._taint_env:
                    node_taint = self._taint_env[var_name]
            
            # For compound expressions, merge taint from children
            for child in n.children:
                child_taint = visit(child)
                node_taint = node_taint.merge(child_taint)
            
            return node_taint
        
        return visit(node)

    def _ts_detect_security_ops(self, node: "Node") -> Dict[str, bool]:
        """Detect security-relevant operations via AST traversal."""
        from .taint.patterns import get_all_sinks_for_language
        
        has_file = False
        has_network = False
        has_subprocess = False
        has_eval = False
        has_sql = False
        has_deserialization = False
        
        # Get comprehensive sink patterns for this language
        sinks = get_all_sinks_for_language(self.language)
        command_sinks = sinks.get("command", set())
        sql_sinks = sinks.get("sql", set())
        eval_sinks = sinks.get("eval", set())
        file_sinks = sinks.get("file", set())
        network_sinks = sinks.get("network", set())
        deser_sinks = sinks.get("deserialization", set())
        
        def matches_sink(func_text: str, sink_set: set) -> bool:
            """Check if function text matches any sink pattern."""
            # Normalize the function text
            normalized = func_text.replace("::", ".").replace("->", ".")
            parts = normalized.split(".")
            func_name = parts[-1] if parts else normalized
            
            for sink in sink_set:
                # Normalize sink pattern too
                sink_normalized = sink.replace("::", ".").replace("->", ".")
                sink_parts = sink_normalized.split(".")
                sink_func = sink_parts[-1] if sink_parts else sink_normalized
                
                # Exact match (normalized)
                if normalized == sink_normalized:
                    return True
                # Function name match
                if func_name == sink_func:
                    return True
                # Partial match (sink pattern in function text)
                if sink_normalized in normalized:
                    return True
            return False
        
        def visit(n: "Node"):
            nonlocal has_file, has_network, has_subprocess, has_eval, has_sql, has_deserialization
            
            # Check call expressions (expanded for all languages)
            if n.type in ("call_expression", "method_invocation", "function_call_expression",
                         "member_call_expression", "scoped_call_expression", "call", "method_call",
                         "invocation_expression", "object_creation_expression", "new_expression"):
                func = n.child_by_field_name("function") or n.child_by_field_name("name") or n.child_by_field_name("method")
                if func:
                    func_text = self._ts_get_node_text(func)
                else:
                    func_text = self._ts_get_node_text(n)
                
                # Check against sink patterns
                if matches_sink(func_text, command_sinks):
                    has_subprocess = True
                if matches_sink(func_text, sql_sinks):
                    has_sql = True
                if matches_sink(func_text, eval_sinks):
                    has_eval = True
                if matches_sink(func_text, file_sinks):
                    has_file = True
                if matches_sink(func_text, network_sinks):
                    has_network = True
                if matches_sink(func_text, deser_sinks):
                    has_deserialization = True
            
            for child in n.children:
                visit(child)
        
        visit(node)
        
        return {
            "has_file_operations": has_file,
            "has_network_operations": has_network,
            "has_subprocess_calls": has_subprocess,
            "has_eval_exec": has_eval,
            "has_sql_operations": has_sql,
            "has_deserialization": has_deserialization,
        }
