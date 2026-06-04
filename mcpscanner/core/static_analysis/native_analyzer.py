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
from typing import Any, Dict, Iterator, List, Optional, Set, Union

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


# Process-wide cache of tree-sitter ``Language`` and ``Parser`` objects,
# keyed by our internal language identifier. Constructing a ``Language``
# from a grammar pointer is cheap individually but becomes a noticeable
# fraction of CPU when ``NativeAnalyzer`` instantiates a fresh
# ``Parser`` per file (and ``extract_mcp_capability_contexts`` *also*
# instantiates one). The ``tree-sitter`` Python bindings document
# ``Parser`` as reusable across ``parse()`` calls, so caching is safe.
#
# We never invalidate this cache — the underlying language modules are
# pinned via ``pyproject.toml`` and the language object is pure data.
_TS_LANGUAGE_CACHE: Dict[str, Optional[Language]] = {}
_TS_PARSER_CACHE: Dict[str, Optional[Parser]] = {}


def _get_tree_sitter_parser(language: str) -> Optional[Parser]:
    """Return a cached, reusable ``Parser`` for the requested language.

    Returns ``None`` when:
    - the language module isn't installed (tree-sitter-<lang> missing), or
    - the language identifier isn't supported.

    Subsequent calls for the same language return the same parser
    instance, so callers must NOT mutate parser-wide options.
    """
    cached = _TS_PARSER_CACHE.get(language)
    if cached is not None:
        return cached
    # Honor a previously cached negative result so we don't repeatedly
    # attempt to import a missing language module.
    if language in _TS_PARSER_CACHE and cached is None:
        return None

    lang_mod = _get_language_module(language)
    if lang_mod is None:
        _TS_PARSER_CACHE[language] = None
        _TS_LANGUAGE_CACHE[language] = None
        return None

    try:
        if language == "typescript":
            lang = Language(lang_mod.language_typescript())
        elif language == "php":
            lang = Language(lang_mod.language_php())
        else:
            lang = Language(lang_mod.language())
    except Exception:
        _TS_PARSER_CACHE[language] = None
        _TS_LANGUAGE_CACHE[language] = None
        return None

    parser = Parser(lang)
    _TS_LANGUAGE_CACHE[language] = lang
    _TS_PARSER_CACHE[language] = parser
    return parser


# Method names that MCP SDKs use to register tools/prompts/resources at
# call sites. Lowercased; the observed call name is lowercased before
# comparing. Verified against the upstream SDK READMEs (TS SDK v1/v2, Go
# SDK ``mcp.AddTool``, Kotlin SDK ``server.addTool``) so the list stays
# narrow and avoids matching unrelated ``.tool``/``.prompt`` collisions.
#
# Templates (``addResourceTemplate``, ``registerResourceTemplate``,
# ``addPromptTemplate``, ``registerPromptTemplate``) are recognized too
# but normalized to their base capability kind in
# ``_normalize_capability`` and tagged with a ``.template`` subtype by
# ``_classify_template_subtype`` so reporting can distinguish them.
_MCP_REGISTRATION_METHODS: Set[str] = {
    # tools
    "tool",
    "registertool",
    "addtool",
    # prompts
    "prompt",
    "registerprompt",
    "addprompt",
    "prompttemplate",
    "registerprompttemplate",
    "addprompttemplate",
    # resources (concrete)
    "resource",
    "registerresource",
    "addresource",
    # resource templates
    "resourcetemplate",
    "registerresourcetemplate",
    "addresourcetemplate",
}


# Low-level SDK registration methods. These pass an MCP request schema
# identifier (``CallToolRequestSchema``, ``ListToolsRequestSchema``, …)
# as the first positional argument and the handler as the second. The
# schema identifier is what discriminates the capability kind, not the
# method name. See ``_LOW_LEVEL_SCHEMA_TO_CAPABILITY`` below.
_MCP_LOW_LEVEL_REGISTRATION_METHODS: Set[str] = {
    "setrequesthandler",
}


# Maps the leading ``*RequestSchema`` identifier (TS low-level SDK) to
# the canonical capability kind. Lowercased for comparison.
_LOW_LEVEL_SCHEMA_TO_CAPABILITY: Dict[str, str] = {
    "calltoolrequestschema": "tool",
    "listtoolsrequestschema": "tool",
    "calltoolresultschema": "tool",
    "callpromptrequestschema": "prompt",
    "listpromptsrequestschema": "prompt",
    "getpromptrequestschema": "prompt",
    "readresourcerequestschema": "resource",
    "listresourcesrequestschema": "resource",
    "listresourcetemplatesrequestschema": "resource",
    "subscriberequestschema": "resource",
    "unsubscriberequestschema": "resource",
}


# Canonical capability suffixes used in Python decorators (e.g. `@mcp.tool`,
# `@hello_mcp.prompt`, or the bare `@resource`). Both FastMCP-style
# (``@mcp.tool``) and low-level Server-style (``@server.call_tool``,
# ``@server.list_tools``, ``@server.read_resource``, ``@server.get_prompt``)
# decorators are recognized.
_PY_MCP_CAPABILITY_TAGS = ("tool", "prompt", "resource")
_PY_MCP_LOWLEVEL_DECORATORS: Dict[str, str] = {
    # FastMCP / high-level shorthand
    "tool": "tool",
    "prompt": "prompt",
    "resource": "resource",
    # Low-level Server (mcp.server.Server)
    "call_tool": "tool",
    "list_tools": "tool",
    "list_prompts": "prompt",
    "get_prompt": "prompt",
    "list_resources": "resource",
    "list_resource_templates": "resource",
    "read_resource": "resource",
    "subscribe_resource": "resource",
    "unsubscribe_resource": "resource",
}


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
    """Map a raw SDK method name onto the canonical capability kind.

    Templates (``addResourceTemplate``, ``registerPromptTemplate``)
    collapse to their base kind so downstream filtering keeps working;
    callers who need to distinguish templates from concrete primitives
    look at the ``.template`` decorator-tag subtype instead.
    """
    lowered = method_name.lower()
    if "prompt" in lowered:
        return "prompt"
    if "resource" in lowered:
        return "resource"
    return "tool"


def _classify_template_subtype(method_name: str) -> Optional[str]:
    """Return ``'template'`` for ``*Template`` registrations, else ``None``.

    The capability kind itself is unchanged (a template is still a
    prompt/resource), but downstream consumers can branch on the
    ``<registration>.<kind>.template`` tag emitted into ``decorator_types``.
    """
    return "template" if "template" in method_name.lower() else None


def _python_decorator_capability(name: str) -> Optional[str]:
    """Return the canonical capability kind for a Python decorator name.

    Accepts the raw decorator strings recorded by Python AST extraction,
    which look like ``mcp.tool``, ``hello_mcp.prompt``, ``server.call_tool``,
    or just ``tool`` for bare decorators. The suffix after the last dot
    is matched against both the FastMCP shorthand (``tool`` / ``prompt`` /
    ``resource``) and the low-level Server-style decorators
    (``call_tool``, ``list_tools``, ``read_resource``, ``get_prompt``,
    ``list_*``). Returns the canonical capability kind or ``None``.
    """
    if not name:
        return None
    bare = name.rsplit(".", 1)[-1]
    bare = bare.split("(", 1)[0].strip().lower()
    return _PY_MCP_LOWLEVEL_DECORATORS.get(bare)


def _is_mcp_capability_decorator_set(decorator_types: Optional[List[str]]) -> bool:
    """Return True if any decorator names an MCP capability.

    Recognizes both FastMCP (``@mcp.tool``, ``@hello_mcp.prompt``) and
    low-level Server (``@server.call_tool``, ``@server.list_tools``,
    ``@server.read_resource``, ``@server.get_prompt``, etc.) decorators.
    """
    if not decorator_types:
        return False
    for dec in decorator_types:
        if _python_decorator_capability(dec) is not None:
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


# Exact identifier allow-list per language. Replaces the old substring
# check (``if 'tool' in 'Tooltip'``) so unrelated annotations like
# ``@Tooltip``, ``@ToolbarItem``, ``[ResourceLock]``, ``#[tool_router]``
# don't classify as MCP capabilities. Identifiers are compared in their
# **original case** so we can distinguish ``@Tool`` (Spring AI MCP
# annotation) from ``@tool`` (Rust rmcp macro) — both legitimate but in
# different languages. The map's value is the canonical capability kind.
#
# Generic identifiers (``Tool``, ``Prompt``, ``Resource``) are accepted
# only when the namespace is in ``_TRUSTED_ANNOTATION_NAMESPACES`` for
# that language — a bare ``@Tool`` is the canonical Spring AI MCP form
# but ``@some.other.lib.Tool`` shouldn't classify just because ``Tool``
# appears at the leaf.
_MCP_ANNOTATION_IDENTIFIERS: Dict[str, Dict[str, str]] = {
    "java": {
        # Spring AI MCP annotations
        "Tool": "tool",
        "McpTool": "tool",
        "ToolParam": "tool",
        "McpResource": "resource",
        "Resource": "resource",
        "McpPrompt": "prompt",
        "Prompt": "prompt",
    },
    "c_sharp": {
        # .NET MCP SDK attributes
        "McpServerTool": "tool",
        "McpServerPrompt": "prompt",
        "McpServerResource": "resource",
        "McpServerToolType": "tool",
        # Generic forms only accepted via trusted namespace check
        "Tool": "tool",
        "Prompt": "prompt",
        "Resource": "resource",
    },
    "rust": {
        # rmcp macros
        "tool": "tool",
        "prompt": "prompt",
        "resource": "resource",
        # Note: ``tool_router``, ``tool_handler`` are intentionally
        # absent. They mark the *router* / *dispatch* impl block, not
        # individual tool callables. The capability extractor walks
        # into the impl and matches the per-method ``#[tool]`` macros.
    },
    "php": {
        # php-mcp/server attributes
        "Tool": "tool",
        "McpTool": "tool",
        "Prompt": "prompt",
        "McpPrompt": "prompt",
        "Resource": "resource",
        "McpResource": "resource",
    },
    "ruby": {
        # mcp-rb / community Ruby SDKs use comment-style annotations
        # (``# @tool name: ...``); identifiers are lowercase by convention.
        "tool": "tool",
        "prompt": "prompt",
        "resource": "resource",
    },
    "python": {
        # Used by the Python branch when a tree-sitter style annotation
        # text (``@<obj>.tool``) is fed back through the same classifier.
        "tool": "tool",
        "prompt": "prompt",
        "resource": "resource",
        # Low-level server decorators
        "call_tool": "tool",
        "list_tools": "tool",
        "get_prompt": "prompt",
        "list_prompts": "prompt",
        "read_resource": "resource",
        "list_resources": "resource",
        "list_resource_templates": "resource",
    },
}

# Namespace prefixes that, when present in front of a generic
# identifier (``Tool`` / ``Prompt`` / ``Resource``), let it classify as
# MCP. Prevents false positives from unrelated DSLs that happen to use
# the same leaf name (e.g. JUnit ``@ToolProvider``, JSF ``@Resource``).
# The empty string represents "no namespace" — i.e. a bare identifier
# at the import root, which we treat as trusted because the caller
# already has to import the symbol from the MCP SDK to use it.
_TRUSTED_ANNOTATION_NAMESPACES: Dict[str, Set[str]] = {
    "java": {"", "org.springframework.ai", "io.modelcontextprotocol"},
    "c_sharp": {"", "ModelContextProtocol", "ModelContextProtocol.Server"},
    "rust": {"", "rmcp", "mcp"},
    "php": {"", "PhpMcp", "PhpMcp\\Server", "PhpMcp\\Server\\Attributes"},
    "ruby": {""},
    "python": {""},
}


# Module/package specifiers (lowercased substrings) that indicate the
# import is from a recognized MCP SDK. Used by Pass 2's receiver
# verification (Gap 4) to decide whether the local name being called
# was actually bound to an MCP server. Anything not on this list is
# treated as belonging to an unrelated DSL and skipped.
_MCP_SDK_MODULE_PREFIXES: Dict[str, "tuple[str, ...]"] = {
    "javascript": (
        "@modelcontextprotocol/sdk",
        "@modelcontextprotocol/typescript-sdk",
    ),
    "typescript": (
        "@modelcontextprotocol/sdk",
        "@modelcontextprotocol/typescript-sdk",
    ),
    "python": (
        "fastmcp",
        "mcp.server",
        "mcp.types",
        "modelcontextprotocol",
    ),
    "go": (
        "modelcontextprotocol/go-sdk",
        "modelcontextprotocol/go-sdk/mcp",
    ),
    "rust": (
        "rmcp",
        "modelcontextprotocol",
    ),
    "kotlin": (
        "io.modelcontextprotocol",
    ),
    "java": (
        "io.modelcontextprotocol",
        "org.springframework.ai",
    ),
    "c_sharp": (
        "modelcontextprotocol",
    ),
    "php": (
        "phpmcp",
        "modelcontextprotocol",
    ),
    "ruby": (
        "mcp",
    ),
}


# Class names exposed by recognized MCP SDKs that, when instantiated and
# bound to a local name, mark that name as a trusted receiver for
# call-site registration detection.
_MCP_KNOWN_SERVER_CLASSES: Set[str] = {
    # TS / JS
    "McpServer",
    "Server",
    "FastMCP",
    # Python
    "Server",
    # Kotlin
    "Server",
    # .NET (uncommon — usually attribute-driven, not instance-bound)
    "McpServer",
}


# Byte-level prefilter (Gap 12). A single compiled regex matched against
# the file's raw bytes; any hit means the file is *worth* parsing. The
# token list covers the surface every supported SDK exposes so we don't
# need a per-language prefilter — one cheap pass before tree-sitter.
#
# Tokens are conservative: anything an MCP SDK or annotation/macro form
# would emit. False-positive cost is paying for one tree-sitter parse;
# false-negative cost is silently skipping a real MCP server, so we
# err on the side of over-matching.
_MCP_PREFILTER_RE = _re.compile(
    rb"(?:"
    rb"@modelcontextprotocol/sdk"  # JS/TS module specifier
    rb"|modelcontextprotocol/go-sdk"  # Go module path
    rb"|modelcontextprotocol\.kotlin"  # Kotlin SDK
    rb"|io\.modelcontextprotocol"  # Java/Kotlin SDK
    rb"|org\.springframework\.ai"  # Spring AI MCP
    rb"|ModelContextProtocol"  # .NET SDK
    rb"|fastmcp"  # Python FastMCP
    rb"|mcp\.server"  # Python low-level Server
    rb"|McpServer"  # JS/TS / .NET class
    rb"|FastMCP\("  # Python instantiation
    rb"|McpServerTool"  # .NET attribute
    rb"|@McpTool"  # Spring AI MCP annotation
    rb"|@McpResource"
    rb"|@McpPrompt"
    rb"|@Tool\b"  # Java MCP annotation
    rb"|#\s*\[\s*tool\b"  # Rust attribute macro
    rb"|#\s*\[\s*Tool\b"  # PHP 8 attribute
    rb"|#\s*\[\s*McpTool\b"  # PHP 8 attribute
    rb"|#\s*@\s*tool\b"  # Ruby comment-style annotation
    rb"|registerTool\b|registerPrompt\b|registerResource\b"
    rb"|registerResourceTemplate\b|registerPromptTemplate\b"
    rb"|addTool\b|addPrompt\b|addResource\b"
    rb"|addResourceTemplate\b|addPromptTemplate\b"
    rb"|setRequestHandler\b"
    rb"|@server\.call_tool\b|@server\.list_tools\b"
    rb"|@server\.list_prompts\b|@server\.get_prompt\b"
    rb"|@server\.list_resources\b|@server\.read_resource\b"
    rb"|@mcp\.tool\b|@mcp\.prompt\b|@mcp\.resource\b"
    rb"|rmcp::|use\s+rmcp"  # Rust SDK
    rb")",
    _re.IGNORECASE,
)


# Per-language prefilter scope. Files whose source bytes contain none of
# the marker tokens above are skipped by the prefilter — but only for
# languages we actually support. Languages that fall outside this set
# (CSS, JSON, etc.) are skipped earlier by ``self.language`` checks.
_PREFILTER_LANGUAGES: Set[str] = {
    "python",
    "javascript",
    "typescript",
    "go",
    "rust",
    "java",
    "kotlin",
    "c_sharp",
    "php",
    "ruby",
}


def _split_annotation_namespace(ident_or_path: str) -> "tuple[str, str]":
    """Split ``rmcp::tool`` / ``mcp::tool`` / ``Tool`` into (namespace, leaf).

    Supports Rust ``::`` path separators, PHP ``\\`` separators, and dot
    separators. Returns ``("", ident)`` when there's no separator.
    """
    for sep in ("::", "\\", "."):
        if sep in ident_or_path:
            ns, _, leaf = ident_or_path.rpartition(sep)
            return ns, leaf
    return "", ident_or_path


def _classify_mcp_annotation(
    annotations: List[str], language: str = ""
) -> Optional[str]:
    """Return ``'tool'`` / ``'prompt'`` / ``'resource'`` if any annotation
    names an MCP capability; otherwise ``None``.

    Uses the per-language exact-identifier allow-list defined in
    ``_MCP_ANNOTATION_IDENTIFIERS`` so that look-alike annotations
    (``@Tooltip``, ``[ResourceLock]``, ``#[tool_router]``, ``@Toolkit``,
    ``@PromptUser``) don't false-positive as MCP capabilities. Generic
    identifiers (``Tool`` / ``Prompt`` / ``Resource`` without a vendor
    prefix) are only accepted when the annotation's namespace is in
    ``_TRUSTED_ANNOTATION_NAMESPACES`` for the active language.

    The ``language`` argument keeps the cross-language allow-list scoped
    correctly (case-sensitive Java ``@Tool`` vs case-sensitive Rust
    ``#[tool]``). When omitted, falls back to the union across all
    languages — only the Python branch should rely on that fallback.
    """
    if language and language in _MCP_ANNOTATION_IDENTIFIERS:
        allowed = _MCP_ANNOTATION_IDENTIFIERS[language]
        trusted_ns = _TRUSTED_ANNOTATION_NAMESPACES.get(language, {""})
    else:
        # Fallback: union across all languages. Only the empty namespace
        # is trusted in this mode.
        allowed = {}
        for tbl in _MCP_ANNOTATION_IDENTIFIERS.values():
            allowed.update(tbl)
        trusted_ns = {""}

    for ann in annotations or []:
        if not ann:
            continue
        for m in _MCP_ANNOTATION_RE.finditer(ann):
            ident = m.group(1)
            # Reconstruct namespace by walking back through the pre-match
            # text for ``::`` / ``\\`` / ``.`` separated segments.
            prefix = ann[: m.start(1)]
            ns_match = _re.search(r"((?:[\w]+(?:::|\\|\.))*)$", prefix)
            namespace = (ns_match.group(1).rstrip(":\\.") if ns_match else "")

            cap = allowed.get(ident)
            if cap is None:
                continue

            # Generic leaves (``Tool`` / ``Prompt`` / ``Resource``) need a
            # trusted namespace. Vendor-prefixed leaves (``McpServerTool``)
            # are accepted unconditionally because they only collide with
            # MCP itself.
            is_generic = ident in {"Tool", "Prompt", "Resource", "tool", "prompt", "resource"}
            if is_generic and namespace not in trusted_ns:
                continue

            return cap
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

        # Gap 12: byte-level prefilter — skip the whole tree-sitter
        # parse for files that contain none of the MCP marker tokens.
        if not self._has_mcp_markers():
            return []

        if self.language not in self.FUNCTION_NODE_TYPES:
            return []

        # Reuse the process-wide cached parser. ``extract_mcp_capability_contexts``
        # is the hot path of the behavioral analyzer — paying for a fresh
        # ``Language`` + ``Parser`` per file is pure overhead because both
        # objects are pure data and reusable.
        #
        # Additionally, when the caller already built a cross-file call
        # graph (which itself parses every survivor file once), prefer
        # the tree it already cached so we don't pay for a *second*
        # parse on each file in directory scans. ``TreeSitterCallGraphAnalyzer``
        # exposes ``get_tree(Path)`` for exactly this case.
        tree = None
        if cross_file_analyzer is not None:
            getter = getattr(cross_file_analyzer, "get_tree", None)
            if callable(getter):
                try:
                    tree = getter(self.file_path)
                except Exception:
                    tree = None

        if tree is None:
            parser = _get_tree_sitter_parser(self.language)
            if parser is None:
                return []
            try:
                tree = parser.parse(self.source_bytes)
            except Exception as e:
                self.logger.warning(
                    f"MCP capability extraction failed for {self.file_path}: {e}"
                )
                return []

        try:
            imports = self._ts_extract_imports(tree.root_node)
        except Exception as e:
            self.logger.warning(
                f"MCP capability extraction failed for {self.file_path}: {e}"
            )
            return []

        func_types = self.FUNCTION_NODE_TYPES.get(self.language, set())
        contexts: List[FunctionContext] = []
        # Dedupe by ``(handler_start_byte, capability_kind)`` so a single
        # function registered as BOTH a tool and a prompt (legal in MCP)
        # surfaces twice — once per capability kind — instead of being
        # collapsed by whichever pass reaches it first. The kind is a
        # str (``"tool"`` / ``"prompt"`` / ``"resource"``); see Gap 9 in
        # the PR review.
        seen_handlers: Set["tuple[int, str]"] = set()

        # Gap 13: build the annotation index once, then look up
        # annotations per function via dict lookup instead of paying
        # for ``_ts_collect_function_annotations`` (a parent walk +
        # sibling scan) on every helper.
        annotation_index = self._ts_build_annotation_index(
            tree.root_node, func_types
        )

        # -----------------------------------------------------------------
        # Pass 1: function-attached annotation/attribute/macro detection
        # -----------------------------------------------------------------
        def visit_funcs(node):
            if (
                node.type in func_types
                and node.type not in _TS_NON_FUNCTION_NODE_TYPES
            ):
                annotations = annotation_index.get(node.start_byte, [])
                cap_kind = _classify_mcp_annotation(annotations, self.language)
                # Dedupe key includes capability kind so the same handler
                # registered as both a tool AND a prompt yields one
                # context per kind. See _append_capability_context which
                # also de-dupes within a single kind via the same set.
                cap_key = (node.start_byte, cap_kind) if cap_kind else None
                if cap_kind is not None and cap_key not in seen_handlers:
                    seen_handlers.add(cap_key)
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
        # Build a per-file index of trusted MCP receiver names (Gap 4) so
        # ``Pass 2`` can require ``X.tool(...)`` / ``X.registerTool(...)``
        # / etc. to have ``X`` resolve to an instance imported from the
        # MCP SDK. Stops unrelated builder DSLs (``myToolbar.tool('save')``)
        # from false-positive-classifying as MCP registrations.
        mcp_instances = self._collect_mcp_instances(tree.root_node, imports)

        registrations = self._ts_find_mcp_registrations(
            tree.root_node, trusted_receivers=mcp_instances
        )
        for reg in registrations:
            handler_node = reg.get("handler_node")
            handler_name = reg.get("handler_name")
            handler_origin: str = "inline"

            if handler_node is None and handler_name:
                handler_node = self._ts_find_function_def_by_name(
                    tree.root_node, handler_name, func_types
                )
                if handler_node is not None:
                    handler_origin = "in_file"

            # Gap 2: cross-file resolution. If the handler is a bare
            # identifier and the in-file symbol index missed it, try the
            # cross-file call graph (tree-sitter or Python) before giving
            # up. The call graph keys functions by ``"<file>::<name>"``,
            # so we match on the suffix.
            cross_file_match: Optional["tuple[str, Any]"] = None
            if handler_node is None and handler_name and cross_file_analyzer is not None:
                cross_file_match = self._resolve_cross_file_handler(
                    handler_name, cross_file_analyzer
                )

            cap_kind = reg["capability"]

            # Gap 8: emit an ``unresolved`` placeholder when the handler
            # cannot be located in-file or cross-file. Without this, the
            # capability is silently dropped and the alignment LLM never
            # sees it. Stub contexts are tagged
            # ``<registration>.unresolved.<kind>`` so consumers can
            # distinguish them from analyzed handlers.
            if handler_node is None and cross_file_match is None:
                if not (handler_name or reg.get("name")):
                    continue
                template_subtype = reg.get("template_subtype")
                source_kind = (
                    "registration.unresolved.template"
                    if template_subtype == "template"
                    else "registration.unresolved"
                )
                # Use the call site's start byte as the dedupe key — the
                # capability extracted is the registration itself, not a
                # specific function.
                stub_key = (id(reg), cap_kind)
                if stub_key in seen_handlers:
                    continue
                seen_handlers.add(stub_key)
                self._append_unresolved_capability(
                    contexts,
                    capability=cap_kind,
                    registered_name=reg.get("name") or handler_name,
                    source_kind=source_kind,
                    handler_name_hint=handler_name,
                )
                continue

            if handler_node is None and cross_file_match is not None:
                # Cross-file hit: build a stub context that points at the
                # defining file/line via the call-graph node.
                cross_file_path, _ = cross_file_match
                template_subtype = reg.get("template_subtype")
                source_kind = (
                    "registration.cross_file.template"
                    if template_subtype == "template"
                    else "registration.cross_file"
                )
                stub_key = (
                    f"{cross_file_path}::{handler_name}",
                    cap_kind,
                )
                if stub_key in seen_handlers:
                    continue
                seen_handlers.add(stub_key)
                self._append_unresolved_capability(
                    contexts,
                    capability=cap_kind,
                    registered_name=reg.get("name") or handler_name,
                    source_kind=source_kind,
                    handler_name_hint=handler_name,
                    source_file=cross_file_path,
                )
                continue

            cap_key = (handler_node.start_byte, cap_kind)
            if cap_key in seen_handlers:
                continue
            seen_handlers.add(cap_key)

            # Tag templates with a ``.template`` subtype so reports can
            # distinguish ``addResourceTemplate`` from ``addResource``.
            template_subtype = reg.get("template_subtype")
            source_kind = (
                "registration.template"
                if template_subtype == "template"
                else "registration"
            )

            self._append_capability_context(
                contexts,
                handler_node,
                imports,
                capability=cap_kind,
                registered_name=reg.get("name"),
                source_kind=source_kind,
            )

        return contexts

    def _resolve_cross_file_handler(
        self, handler_name: str, cross_file_analyzer: Any
    ) -> Optional["tuple[str, Any]"]:
        """Look ``handler_name`` up in a cross-file call graph (Gap 2).

        Both ``CallGraph`` (Python) and ``TSCallGraph`` (tree-sitter)
        store function definitions as
        ``Dict[str, Node]`` keyed by ``f"{file_path}::{name}"``. We
        match on the suffix because the registration call site only
        knows the bare identifier — it doesn't know the defining file.

        Returns ``(defining_file_path_str, node)`` on the first match,
        or ``None`` if the identifier isn't in either analyzer's graph.
        """
        graph = getattr(cross_file_analyzer, "call_graph", None)
        if graph is None:
            return None
        functions = getattr(graph, "functions", None)
        if not functions:
            return None
        suffix = f"::{handler_name}"
        for full_name, node in functions.items():
            if full_name.endswith(suffix):
                file_path = full_name[: -len(suffix)]
                return file_path, node
        return None

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

    # -------------------------------------------------------------------------
    # Helpers for the new lazy/single-pass paths
    # -------------------------------------------------------------------------

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

    def _py_extract_capability_contexts(
        self,
        cross_file_analyzer: Optional[Any] = None,
    ) -> List[FunctionContext]:
        """Lazy Python capability extraction (Gap 5 + Gap 8).

        The previous implementation called ``extract_all_function_contexts``
        which forced a full ForwardDataflowAnalysis pass on every helper
        function in the file *before* filtering them out — defeating the
        purpose of the capability extractor on helper-heavy modules.

        The new path:

          1. Run the byte-level prefilter once. If the file has no MCP
             markers, return ``[]`` without parsing.
          2. ``ast.parse`` once — or, when the caller's
             ``cross_file_analyzer`` (a ``CallGraphAnalyzer``) already
             parsed the same file, reuse its cached AST instead of
             paying for a duplicate parse (Gap 4: deduplicate
             parse/read).
          3. Walk the AST and collect:
             a. ``FunctionDef`` / ``AsyncFunctionDef`` nodes whose
                decorator list names an MCP capability (FastMCP
                shorthand or low-level Server).
             b. Wrapper-decorator targets (Gap 8): functions decorated
                with custom wrappers that internally call
                ``mcp.tool(...)``. Detected via a per-file scan that
                identifies wrapper definitions like
                ``def safe_tool(fn): return mcp.tool()(fn)``.
             c. Programmatic ``mcp.add_tool(handler)`` /
                ``server.add_tool(handler)`` calls (Gap 8): emit the
                handler if it's a known function, an unresolved stub
                otherwise.
          4. Run the expensive ``_py_extract_function`` (which triggers
             dataflow analysis) ONLY on the filtered candidates.

        Falls back to ``extract_all_function_contexts``-and-filter if
        the lazy path raises so behavior stays robust.
        """
        if not self._has_mcp_markers():
            return []

        tree = None
        if cross_file_analyzer is not None:
            getter = getattr(cross_file_analyzer, "get_ast", None)
            if callable(getter):
                try:
                    tree = getter(self.file_path)
                except Exception:
                    tree = None

        if tree is None:
            try:
                tree = ast.parse(self.source_code, filename=str(self.file_path))
            except SyntaxError:
                return []

        module_imports = self._py_extract_imports(tree)
        wrapper_decorators = self._py_collect_wrapper_decorators(tree)

        functions_by_name: Dict[
            str, Union[ast.FunctionDef, ast.AsyncFunctionDef]
        ] = {}
        for n in ast.walk(tree):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                functions_by_name.setdefault(n.name, n)

        # Class-method index for ``self.<method>`` resolution at
        # registration call sites (Gap 8 extension).
        class_methods = self._py_build_class_method_index(tree)

        contexts: List[FunctionContext] = []
        seen: Set["tuple[Any, str]"] = set()

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            decorator_names = [
                self._py_get_node_name(dec) for dec in (node.decorator_list or [])
            ]
            cap_kind = self._py_classify_decorators(
                decorator_names, wrapper_decorators
            )
            if cap_kind is None:
                continue
            cap_key = (node.lineno, cap_kind)
            if cap_key in seen:
                continue
            seen.add(cap_key)
            try:
                ctx = self._py_extract_function(node, module_imports)
            except Exception as e:
                self.logger.debug(
                    f"Failed to extract MCP capability {node.name!r} from "
                    f"{self.file_path}: {e}"
                )
                continue
            contexts.append(ctx)

        # Gap 8: programmatic registrations.
        # Covers both ``mcp.add_tool(fn)`` and the
        # ``mcp.tool(...)(self.method)`` decorator-factory-on-bound-method
        # pattern (used by AWS-Labs-style tool-group classes). Handlers
        # we cannot resolve in-file (cross-file references, factory
        # calls, etc.) become unresolved-handler stubs so the LLM /
        # report layer still sees a capability was registered.
        for handler_node, label, cap_kind in self._py_iter_programmatic_registrations(
            tree,
            functions_by_name=functions_by_name,
            class_methods=class_methods,
        ):
            if handler_node is None:
                stub_key = (("unresolved", label), cap_kind)
                if stub_key in seen:
                    continue
                seen.add(stub_key)
                self._append_unresolved_capability(
                    contexts,
                    capability=cap_kind,
                    registered_name=label,
                    source_kind="registration.unresolved",
                    handler_name_hint=label,
                )
                continue
            cap_key = (handler_node.lineno, cap_kind)
            if cap_key in seen:
                continue
            seen.add(cap_key)
            try:
                ctx = self._py_extract_function(handler_node, module_imports)
            except Exception as e:
                self.logger.debug(
                    f"Failed to extract programmatic MCP capability "
                    f"{label!r}: {e}"
                )
                continue
            ctx.decorator_types.append(f"<registration>.{cap_kind}")
            contexts.append(ctx)

        return contexts

    def _py_collect_wrapper_decorators(self, tree: ast.AST) -> Dict[str, str]:
        """Identify custom decorator wrappers that delegate to an MCP
        decorator (Gap 8).

        Recognizes the common pattern::

            def safe_tool(fn):
                return mcp.tool()(fn)

        Returns ``{wrapper_name: capability_kind}``. Wrappers found here
        are accepted by ``_py_classify_decorators`` so a function
        decorated with ``@safe_tool`` is classified as a tool even
        though no built-in MCP decorator name appears on it.
        """
        wrappers: Dict[str, str] = {}
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            # Wrappers usually take a single arg (``fn``) and return a
            # call expression that invokes an MCP decorator on it.
            for ret in (
                stmt
                for stmt in ast.walk(node)
                if isinstance(stmt, ast.Return)
            ):
                if ret.value is None:
                    continue
                cap = self._py_call_returns_mcp_decoration(ret.value)
                if cap is not None:
                    wrappers[node.name] = cap
                    break
        return wrappers

    def _py_call_returns_mcp_decoration(
        self, expr: ast.AST
    ) -> Optional[str]:
        """Return the capability kind if ``expr`` is a call expression
        that ultimately invokes ``mcp.tool``/``mcp.prompt``/``mcp.resource``
        (or one of the low-level server decorators) and applies it to a
        function. Used to detect wrapper decorators (Gap 8)."""
        if not isinstance(expr, ast.Call):
            return None
        # ``mcp.tool()(fn)`` parses as Call(Call(...), [fn])
        inner = expr.func
        if isinstance(inner, ast.Call):
            return self._py_call_returns_mcp_decoration(inner)
        # Plain attribute access: ``server.add_tool(fn)`` etc.
        name_text = self._py_get_node_name(inner)
        if not name_text:
            return None
        return _python_decorator_capability(name_text)

    def _py_classify_decorators(
        self,
        decorator_names: List[str],
        wrapper_decorators: Dict[str, str],
    ) -> Optional[str]:
        """Return the canonical capability kind for ``decorator_names``.

        Accepts both built-in MCP decorators (FastMCP / low-level
        Server) and locally-defined wrapper decorators discovered via
        ``_py_collect_wrapper_decorators``.
        """
        for name in decorator_names or []:
            kind = _python_decorator_capability(name)
            if kind is not None:
                return kind
            bare = name.rsplit(".", 1)[-1].split("(", 1)[0].strip()
            wrapped = wrapper_decorators.get(bare)
            if wrapped:
                return wrapped
        return None

    # ------------------------------------------------------------------
    # Gap 8 (extended): programmatic + decorator-call-on-bound-method
    # ------------------------------------------------------------------

    # ``<obj>.<method>(handler)`` — direct programmatic registration.
    _PY_PROGRAMMATIC_METHOD_TO_KIND: Dict[str, str] = {
        "add_tool": "tool",
        "register_tool": "tool",
        "add_prompt": "prompt",
        "register_prompt": "prompt",
        "add_resource": "resource",
        "register_resource": "resource",
        "add_resource_template": "resource",
        "add_prompt_template": "prompt",
    }

    # ``<obj>.<method>(...)(handler)`` — decorator factory applied to a
    # bound method or function reference. Includes both the FastMCP
    # high-level shorthand and the low-level ``Server`` decorators that
    # users sometimes invoke programmatically (e.g. tests, dynamic
    # registration).
    _PY_DECORATOR_FACTORY_METHOD_TO_KIND: Dict[str, str] = {
        "tool": "tool",
        "prompt": "prompt",
        "resource": "resource",
        "resource_template": "resource",
        "prompt_template": "prompt",
        "call_tool": "tool",
        "list_tools": "tool",
        "list_prompts": "prompt",
        "get_prompt": "prompt",
        "list_resources": "resource",
        "list_resource_templates": "resource",
        "read_resource": "resource",
    }

    def _py_build_class_method_index(
        self, tree: ast.AST
    ) -> Dict[str, Dict[str, Union[ast.FunctionDef, ast.AsyncFunctionDef]]]:
        """Index ``{class_name: {method_name: FunctionDef}}`` for the file.

        Used to resolve ``self.<method>`` references at registration call
        sites such as ``mcp.tool(name='x')(self.do_thing)`` (Gap 8).
        Nested classes shadow earlier definitions of the same name; we
        keep the first occurrence for stability.
        """
        out: Dict[str, Dict[str, Union[ast.FunctionDef, ast.AsyncFunctionDef]]] = {}
        for cls in ast.walk(tree):
            if not isinstance(cls, ast.ClassDef):
                continue
            methods: Dict[str, Union[ast.FunctionDef, ast.AsyncFunctionDef]] = {}
            for stmt in cls.body:
                if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    methods.setdefault(stmt.name, stmt)
            if methods:
                out.setdefault(cls.name, methods)
        return out

    def _py_walk_calls_with_class_context(
        self, node: ast.AST, class_stack: List[str]
    ) -> Iterator["tuple[ast.Call, Optional[str]]"]:
        """Yield ``(Call, enclosing_class_name)`` for every ``ast.Call``.

        Tracks the innermost enclosing ``ClassDef`` so callers can resolve
        ``self.<method>`` handler references against the correct class.
        Nested classes push onto the stack; the current class is the top
        of the stack.
        """
        if isinstance(node, ast.Call):
            yield node, (class_stack[-1] if class_stack else None)
        if isinstance(node, ast.ClassDef):
            new_stack = class_stack + [node.name]
        else:
            new_stack = class_stack
        for child in ast.iter_child_nodes(node):
            yield from self._py_walk_calls_with_class_context(child, new_stack)

    def _py_resolve_handler_expr(
        self,
        handler: ast.expr,
        enclosing_cls: Optional[str],
        class_methods: Dict[
            str, Dict[str, Union[ast.FunctionDef, ast.AsyncFunctionDef]]
        ],
        functions_by_name: Dict[
            str, Union[ast.FunctionDef, ast.AsyncFunctionDef]
        ],
    ) -> "tuple[Optional[Union[ast.FunctionDef, ast.AsyncFunctionDef]], str]":
        """Resolve a handler expression at a registration call site.

        Returns ``(function_node_or_None, human_label)``. When the node
        is ``None`` callers should emit an unresolved-handler stub so
        downstream consumers know a capability was registered without
        silently dropping it.
        """
        if isinstance(handler, ast.Name):
            return functions_by_name.get(handler.id), handler.id
        if isinstance(handler, ast.Attribute) and isinstance(
            handler.value, ast.Name
        ):
            base = handler.value.id
            attr = handler.attr
            if base in ("self", "cls") and enclosing_cls:
                node = class_methods.get(enclosing_cls, {}).get(attr)
                return node, f"{enclosing_cls}.{attr}"
            return None, f"{base}.{attr}"
        # Lambda, factory call, subscript, etc. — surface as unresolved
        # so the LLM still sees that something was registered here.
        return None, "<unresolved>"

    def _py_iter_programmatic_registrations(
        self,
        tree: ast.AST,
        functions_by_name: Optional[
            Dict[str, Union[ast.FunctionDef, ast.AsyncFunctionDef]]
        ] = None,
        class_methods: Optional[
            Dict[
                str,
                Dict[str, Union[ast.FunctionDef, ast.AsyncFunctionDef]],
            ]
        ] = None,
    ) -> List[
        "tuple[Optional[Union[ast.FunctionDef, ast.AsyncFunctionDef]], str, str]"
    ]:
        """Iterate programmatic / indirect MCP registration calls (Gap 8).

        Detects two complementary patterns:

        * **Direct programmatic registration** —
          ``<obj>.add_tool(fn)``, ``<obj>.register_resource(fn)`` and
          their kin. The first positional argument is taken as the
          handler reference.
        * **Decorator-factory applied to a bound method or function** —
          ``<obj>.tool(name='x')(self.do_thing)`` (the form used widely
          by AWS-Labs MCP servers) and the bare
          ``<obj>.tool(self.do_thing)`` shorthand. The decorator factory
          resolves to FastMCP shorthands (``tool``/``prompt``/
          ``resource`` and template variants) or the low-level
          ``Server`` decorators (``call_tool``/``list_tools``/
          ``read_resource``/``get_prompt``/etc.).

        Returns a list of ``(handler_node_or_None, label, capability)``
        tuples. ``handler_node`` is ``None`` for cross-file or factory-
        produced handlers we cannot resolve in-file; callers should emit
        an unresolved-handler stub via
        :py:meth:`_append_unresolved_capability` for those entries.
        """
        functions_by_name = functions_by_name or {}
        class_methods = class_methods or {}

        out: List[
            "tuple[Optional[Union[ast.FunctionDef, ast.AsyncFunctionDef]], str, str]"
        ] = []

        for call, enclosing_cls in self._py_walk_calls_with_class_context(
            tree, []
        ):
            kind: Optional[str] = None
            handler_expr: Optional[ast.expr] = None

            method = self._py_call_method_name(call)
            if (
                method is not None
                and method in self._PY_PROGRAMMATIC_METHOD_TO_KIND
                and call.args
            ):
                kind = self._PY_PROGRAMMATIC_METHOD_TO_KIND[method]
                handler_expr = call.args[0]
            elif isinstance(call.func, ast.Call):
                # ``<obj>.tool(name='x')(handler)`` — decorator factory
                # applied to a function/method reference.
                inner_method = self._py_call_method_name(call.func)
                if (
                    inner_method is not None
                    and inner_method in self._PY_DECORATOR_FACTORY_METHOD_TO_KIND
                    and call.args
                ):
                    kind = self._PY_DECORATOR_FACTORY_METHOD_TO_KIND[
                        inner_method
                    ]
                    handler_expr = call.args[0]

            if kind is None or handler_expr is None:
                continue

            handler_node, label = self._py_resolve_handler_expr(
                handler_expr,
                enclosing_cls,
                class_methods,
                functions_by_name,
            )
            out.append((handler_node, label, kind))

        return out

    def _py_call_method_name(self, call: ast.Call) -> Optional[str]:
        """Return the dotted-leaf method name of an ``ast.Call``."""
        f = call.func
        if isinstance(f, ast.Attribute):
            return f.attr
        if isinstance(f, ast.Name):
            return f.id
        return None

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

    def _ts_build_annotation_index(
        self, root: "Node", func_types: Set[str]
    ) -> Dict[int, List[str]]:
        """Index every function node's annotations in a single tree walk (Gap 13).

        Returns ``{function_start_byte: [annotation_text, ...]}``. Empty
        lists are populated lazily by callers; callers who get a miss can
        treat it as "no annotations" without re-walking. Cached per
        ``(root, language)`` so repeated capability extraction on the
        same file (e.g. across multiple registrations) doesn't re-walk
        the tree.

        Re-uses the same matching rules as
        ``_ts_collect_function_annotations`` (the original per-function
        walker) so the classifier sees identical strings.
        """
        cache_attr = "_annotation_index_cache"
        cached: Optional[Dict[int, List[str]]] = None
        cache_key = (id(root), self.language)
        store = getattr(self, cache_attr, None)
        if store is None:
            store = {}
            setattr(self, cache_attr, store)
        cached = store.get(cache_key)
        if cached is not None:
            return cached

        index: Dict[int, List[str]] = {}

        def visit(node: "Node") -> None:
            if (
                node.type in func_types
                and node.type not in _TS_NON_FUNCTION_NODE_TYPES
            ):
                annotations = self._ts_collect_function_annotations(node)
                if annotations:
                    index[node.start_byte] = annotations
            for child in node.children:
                visit(child)

        visit(root)
        store[cache_key] = index
        return index

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

    def _ts_find_mcp_registrations(
        self,
        root: "Node",
        trusted_receivers: Optional[Set[str]] = None,
    ) -> List[Dict[str, Any]]:
        """Find call expressions that look like MCP capability registrations.

        Returns a list of dicts describing each registration::

            {
                "capability": "tool" | "prompt" | "resource",
                "name": Optional[str],          # the registered MCP name
                "handler_node": Optional[Node], # inline arrow/function expr
                "handler_name": Optional[str],  # identifier ref otherwise
                "template_subtype": Optional[str],  # "template" if applicable
            }

        Walks with a parent pointer so we can recognize Kotlin-style
        trailing lambdas, which tree-sitter parses as a nested call
        expression where the *outer* call's function field is the *inner*
        ``server.addTool(...)`` call and the lambda is the outer call's
        sibling.

        ``trusted_receivers`` (Gap 4) is the per-file set of local names
        that bind to MCP server instances (e.g., ``server`` from
        ``const server = new McpServer(...)`` or ``mcp`` from
        ``mcp = FastMCP(...)``). If supplied, only call expressions whose
        receiver is in this set are accepted. The Go SDK's
        ``mcp.AddTool(server, ...)`` is special-cased: its receiver is
        the imported package alias rather than an instance, so the
        package-level call methods (``addtool``/``addprompt``/...) are
        accepted unconditionally and the first positional argument is
        treated as the server instance.
        """
        registrations: List[Dict[str, Any]] = []
        trusted_receivers = trusted_receivers or set()

        def visit(node: "Node", parent: Optional["Node"]):
            if node.type == "call_expression":
                method = self._ts_call_method_name(node)
                method_lc = method.lower() if method else ""

                is_low_level = method_lc in _MCP_LOW_LEVEL_REGISTRATION_METHODS
                is_registration_method = (
                    method_lc in _MCP_REGISTRATION_METHODS or is_low_level
                )

                if is_registration_method:
                    # Receiver verification: drop unrelated DSLs that
                    # happen to expose ``.tool(...)`` etc.
                    if not self._ts_receiver_is_trusted(
                        node, method_lc, trusted_receivers
                    ):
                        for child in node.children:
                            visit(child, node)
                        return

                    args_node = self._ts_call_arguments_node(node)

                    if is_low_level:
                        # TS low-level Server: capability is determined by
                        # the leading ``*RequestSchema`` identifier, not by
                        # the method name itself.
                        ll_cap = self._ts_low_level_capability(args_node)
                        if ll_cap is None:
                            for child in node.children:
                                visit(child, node)
                            return
                        reg = self._ts_parse_registration_args(
                            args_node, method_lc, override_capability=ll_cap
                        )
                        if reg is None:
                            reg = {
                                "capability": ll_cap,
                                "name": None,
                                "handler_node": None,
                                "handler_name": None,
                            }
                        reg["template_subtype"] = None
                    else:
                        reg = self._ts_parse_registration_args(args_node, method_lc)
                        if reg is None:
                            # No string name and no inline/named handler in
                            # ``arguments``, but the call site itself still
                            # qualifies as a registration; allow Pass 1 (the
                            # trailing-lambda lookup below) to populate the
                            # handler.
                            reg = {
                                "capability": _normalize_capability(method_lc),
                                "name": None,
                                "handler_node": None,
                                "handler_name": None,
                            }
                        reg["template_subtype"] = _classify_template_subtype(method_lc)

                    # Kotlin: ``server.addTool(...) { req -> }``
                    #
                    # Across tree-sitter-kotlin versions a trailing
                    # lambda is exposed in two different ways:
                    #
                    #   (A) Sibling of the ``call_expression``'s args:
                    #       the lambda lives as a direct child of THIS
                    #       call_expression (most current grammar
                    #       versions).
                    #   (B) An OUTER call wraps the inner call; the
                    #       outer's children are the inner call (callee)
                    #       plus the lambda (older grammar versions or
                    #       certain receiver shapes).
                    #
                    # We check both. Walking the call's own children
                    # first is structurally safer because it doesn't
                    # depend on parent-child layout, which is the
                    # specific brittleness called out in Gap 10.
                    if reg.get("handler_node") is None:
                        for child in node.children:
                            lambda_node = self._ts_unwrap_trailing_lambda(child)
                            if lambda_node is not None:
                                reg["handler_node"] = lambda_node
                                break

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

    def _ts_receiver_is_trusted(
        self,
        call_node: "Node",
        method_lc: str,
        trusted_receivers: Set[str],
    ) -> bool:
        """Return True if ``call_node``'s receiver should be honored as MCP.

        - For Go's ``mcp.AddTool(server, ...)``: the receiver is the
          imported package alias (``mcp``); we accept it when the alias
          is in ``trusted_receivers``.
        - For instance methods (``server.tool(...)``): the receiver name
          must be in ``trusted_receivers``.
        - For ``setRequestHandler``: same instance-method rule applies
          but we also accept it when ``trusted_receivers`` is empty,
          since low-level Server use can leave the binding harder to
          detect.
        - When ``trusted_receivers`` is empty (provenance pass produced
          nothing useful), we fall back to the previous loose behavior
          to avoid silently dropping every registration.
        """
        if not trusted_receivers:
            # Loose mode preserves backward compatibility when imports
            # are missing or the file uses unconventional aliasing.
            # Provenance is best-effort, not authoritative.
            return True

        receiver = self._ts_call_receiver_name(call_node) or ""
        if not receiver:
            # Bare ``tool(...)`` calls without a receiver are treated as
            # trusted because they can only have come from a direct
            # import of the SDK function.
            return True
        return receiver in trusted_receivers

    def _ts_call_receiver_name(self, call_node: "Node") -> Optional[str]:
        """Return the receiver expression of a ``X.method(...)`` call.

        For ``mcp.AddTool(...)`` returns ``"mcp"``; for
        ``server.registerTool(...)`` returns ``"server"``; for a plain
        function call without a receiver, returns ``None``.
        """
        func = call_node.child_by_field_name("function")
        if func is None:
            for child in call_node.children:
                if child.type in (
                    "navigation_expression",
                    "member_expression",
                    "selector_expression",
                    "field_access",
                    "method_invocation",
                ):
                    func = child
                    break
        if func is None or func.type not in (
            "navigation_expression",
            "member_expression",
            "selector_expression",
            "field_access",
            "method_invocation",
        ):
            return None

        # JS/TS expose the receiver via the ``object`` field; Go via
        # ``operand``; Kotlin via the first non-trivia child.
        for field in ("object", "operand", "expression"):
            recv = func.child_by_field_name(field)
            if recv is not None:
                return self._ts_get_node_text(recv).strip().split(".")[0]
        for child in func.children:
            if child.is_named:
                return self._ts_get_node_text(child).strip().split(".")[0]
        return None

    def _ts_low_level_capability(
        self, args_node: Optional["Node"]
    ) -> Optional[str]:
        """Return the capability for ``setRequestHandler(<Schema>, ...)``.

        Inspects the first positional argument: if it's an identifier
        like ``CallToolRequestSchema``, ``ListToolsRequestSchema`` etc.,
        maps it via ``_LOW_LEVEL_SCHEMA_TO_CAPABILITY``. Returns ``None``
        if the schema can't be identified.
        """
        if args_node is None:
            return None
        for child in args_node.children:
            if child.type in ("(", ")", ",", "comment"):
                continue
            text = self._ts_get_node_text(child).strip()
            if not text:
                continue
            # Accept both bare identifiers and dotted forms
            # (``Schemas.CallToolRequestSchema``) by taking the leaf.
            leaf = text.rsplit(".", 1)[-1]
            cap = _LOW_LEVEL_SCHEMA_TO_CAPABILITY.get(leaf.lower())
            if cap:
                return cap
            # First positional arg is the schema; if it isn't recognized
            # we don't keep scanning.
            return None
        return None

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

    def _ts_is_mcp_instantiation(
        self, expr_node: "Node", sdk_classes: Set[str]
    ) -> bool:
        """Recognize ``new McpServer(...)`` / ``FastMCP(...)`` etc."""
        if not sdk_classes:
            return False
        if expr_node.type in ("new_expression",):
            cls = expr_node.child_by_field_name("constructor")
            if cls is None:
                for c in expr_node.children:
                    if c.is_named:
                        cls = c
                        break
            if cls is not None:
                cls_name = (
                    self._ts_get_node_text(cls).strip().split(".")[-1]
                )
                return cls_name in sdk_classes
        if expr_node.type == "call_expression":
            callee = expr_node.child_by_field_name("function")
            if callee is None:
                for c in expr_node.children:
                    if c.is_named:
                        callee = c
                        break
            if callee is not None:
                callee_text = self._ts_get_node_text(callee).strip()
                leaf = callee_text.rsplit(".", 1)[-1]
                return leaf in sdk_classes
        return False

    def _ts_is_mcp_factory_call(
        self, expr_node: "Node", sdk_aliases: Set[str]
    ) -> bool:
        """Recognize ``mcp.NewServer(...)`` Go-style factory calls."""
        if not sdk_aliases:
            return False
        if expr_node.type != "call_expression":
            return False
        callee = expr_node.child_by_field_name("function")
        if callee is None:
            for c in expr_node.children:
                if c.is_named:
                    callee = c
                    break
        if callee is None:
            return False
        text = self._ts_get_node_text(callee).strip()
        if "." not in text:
            return False
        receiver, _, method = text.partition(".")
        return (
            receiver in sdk_aliases
            and ("server" in method.lower() or "newserver" in method.lower())
        )

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

        Accepts:

        * ``lambda_literal`` directly,
        * ``annotated_lambda`` (which wraps a ``lambda_literal`` and may
          carry annotations like ``@Suppress``),
        * ``call_suffix`` / ``annotated_call_suffix`` — the synthetic
          parser node that some tree-sitter-kotlin grammar versions
          insert around the trailing lambda position.

        Returns ``None`` if the node isn't a lambda or doesn't wrap one,
        so the caller can keep scanning siblings.
        """
        if node is None:
            return None
        if node.type == "lambda_literal":
            return node
        if node.type in (
            "annotated_lambda",
            "call_suffix",
            "annotated_call_suffix",
        ):
            for sub in node.children:
                lambda_node = self._ts_unwrap_trailing_lambda(sub)
                if lambda_node is not None:
                    return lambda_node
            return node if node.type == "annotated_lambda" else None
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
        self,
        args_node: Optional["Node"],
        capability_method: str,
        override_capability: Optional[str] = None,
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
            "capability": override_capability or _normalize_capability(capability_method),
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
        """Find a function/arrow-function definition by symbol name.

        Backed by ``_ts_build_function_index`` (Gap 6), which walks the
        tree once and caches a ``name -> Node`` map per file. The
        previous implementation walked the AST per registration call,
        producing ``O(registrations × file_size)`` work; the index
        collapses it to a single ``O(file_size)`` walk plus a dict
        lookup for each registration.
        """
        if not target_name:
            return None

        index = self._ts_build_function_index(root, func_types)
        return index.get(target_name)

    def _ts_build_function_index(
        self, root: "Node", func_types: Set[str]
    ) -> Dict[str, "Node"]:
        """Build a ``name -> definition_node`` map for ``root`` (Gap 6).

        Walks the tree once and records:
          * named function/method declarations (``function_declaration``,
            ``method_definition``, etc.),
          * arrow functions / function expressions assigned to a local
            via ``variable_declarator`` / ``assignment`` (``const fn = …``,
            ``fn = …``).

        Cached per (file, language). Subsequent calls reuse the index.
        """
        cache_key = (id(root), self.language)
        cached = getattr(self, "_func_index_cache", None)
        if cached is None:
            cached = {}
            self._func_index_cache = cached
        if cache_key in cached:
            return cached[cache_key]

        index: Dict[str, "Node"] = {}

        def visit(node: "Node") -> None:
            if node.type in func_types:
                name_node = node.child_by_field_name("name")
                if name_node is not None:
                    index.setdefault(self._ts_get_node_text(name_node), node)
                # ``const handler = async (args) => { ... };``
                # ``handler = async (args) => { ... };``
                if node.type in ("arrow_function", "function_expression"):
                    parent = node.parent
                    if parent is not None and parent.type in (
                        "variable_declarator",
                        "assignment",
                        "assignment_expression",
                    ):
                        parent_name = parent.child_by_field_name("name")
                        if parent_name is None:
                            parent_name = parent.child_by_field_name("left")
                        if parent_name is not None:
                            index.setdefault(
                                self._ts_get_node_text(parent_name), node
                            )
            for child in node.children:
                visit(child)

        visit(root)
        cached[cache_key] = index
        return index

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
        # Reuse the process-wide cached parser. Falls back to "module
        # missing" errors only when the language isn't installed.
        parser = _get_tree_sitter_parser(self.language)
        if parser is None:
            return NativeAnalysisResult(
                success=False,
                language=self.language,
                errors=[
                    f"tree-sitter-{self.language} not available. Install: "
                    f"pip install tree-sitter-{self.language.replace('_', '-')}"
                ],
            )

        functions = []
        errors = []

        try:
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
