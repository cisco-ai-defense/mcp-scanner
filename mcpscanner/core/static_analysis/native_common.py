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

"""Shared vocabulary of the native multi-language analyzer.

Language tables, MCP SDK recognition patterns, and the small pure
helpers that both the Python and tree-sitter backends need. Split out of
``native_analyzer`` so the two backends can import them without importing
each other.

Original module docstring follows.

Native Code Analyzer - AST-based multi-language analyzer.

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

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from .context_extractor import FunctionContext
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
                status=TaintStatus.TAINTED, sources=self.sources | other.sources
            )
        return TaintInfo(status=self.status, sources=self.sources.copy())


# Tree-sitter imports - each language is optional
from tree_sitter import Language, Parser, Node  # noqa: F401,E402

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

# Member/property access nodes whose text is preserved as a handler or
# dynamic-name hint (``m.fn``, ``obj.handler``) when bare identifiers are
# absent.
_TS_MEMBER_EXPR_TYPES: Set[str] = {
    "member_expression",
    "property_access_expression",
    "field_expression",
    "selector_expression",
}


# Compiled once: matches an annotation/attribute/macro sigil followed by an
# identifier we want to inspect. Covers:
#   @Tool            Java/Spring AI
#   @McpTool         Spring AI MCP annotations
#   [McpServerTool]  C# attributes
#   #[tool]          Rust attribute macros (and `#[mcp::tool]`)
#   #[Tool]          PHP 8 attributes
#   # @tool          Ruby comment-style annotation
import re as _re  # noqa: E402  (local alias avoids polluting wider module namespace)

# Notes for maintainers:
# - The optional namespace path consumes ``::``, ``.``, *and* ``\\``
#   separators so fully-qualified annotations like
#   ``@org.springframework.ai.Tool``,
#   ``[ModelContextProtocol.Server.McpServerTool]``, and PHP's
#   ``#[App\\Mcp\\Tool]`` still surface the LEAF identifier (``Tool``,
#   ``McpServerTool``) instead of the package head.
# - The captured identifier uses ``\w+`` (no leading ``[A-Za-z_]``
#   class) so its character set doesn't overlap with ``\w``.
#   Identifiers starting with a digit aren't a real concern here
#   because the upstream tokenizers reject them long before this
#   regex sees the source.
_MCP_ANNOTATION_RE = _re.compile(
    r"""
    (?:                                    # one of the annotation sigils
        @\#?                               #   @ or @# (rare)
      | \#\s*\[                            #   # [  (Rust / PHP 8 — note '# ' before '[')
      | \[                                 #   [  (C#)
      | \#\s*@                             #   # @ (Ruby docblock-style)
    )
    \s*
    # Optional namespace path: ``pkg::``, ``pkg.``, or ``pkg\\``
    # (Important: do not end this comment with a backslash — under
    # VERBOSE mode a trailing ``\`` escapes the newline and silently
    # eats the next line of the pattern, killing the capture group.)
    (?:\w+\s*(?:::|\.|\\))*
    (\w+)                                  # ← captured: the leaf identifier
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


# Source-file extensions stripped when normalizing module specifiers to
# path-suffix candidates. Used by both ``_normalize_module_specifier`` and
# ``_path_endswith_suffix`` so the import-map disambiguator survives small
# language differences (``.tsx`` vs ``.ts``, ``.pyi`` vs ``.py``, etc.).
_SOURCE_FILE_EXTS: "tuple[str, ...]" = (
    ".py",
    ".pyi",
    ".pyx",
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".go",
    ".rb",
    ".rs",
    ".kt",
    ".kts",
    ".java",
    ".cs",
    ".php",
    ".m",
)


def _strip_source_extension(p: str) -> str:
    """Strip the trailing language source extension from ``p`` if present."""
    last_seg = p.rsplit("/", 1)[-1]
    for ext in _SOURCE_FILE_EXTS:
        if last_seg.endswith(ext):
            return p[: -len(ext)]
    return p


def _normalize_module_specifier(spec: str) -> str:
    """Normalize an import module specifier into a path-suffix candidate.

    Used by the cross-file handler resolver (Gap 2) to disambiguate
    same-named functions in different files.

    Examples::

        "./tools/add"          -> "tools/add"
        "../tools/add.js"      -> "tools/add"
        "tools.docs"           -> "tools/docs"
        ".tools.docs"          -> "tools/docs"
        "@scope/pkg/sub"       -> "@scope/pkg/sub"
        "github.com/foo/bar"   -> "github.com/foo/bar"
    """
    if not spec:
        return ""
    s = spec.strip()
    # Drop relative-path segments that would otherwise pollute the
    # suffix (``../foo/bar`` should match a file ending in ``foo/bar``).
    while s.startswith("./") or s.startswith("../"):
        s = s[3:] if s.startswith("../") else s[2:]
    # Python-style leading dots (``.tools.docs``).
    s = s.lstrip(".")
    # Strip a trailing source extension if any.
    s = _strip_source_extension(s)
    # Convert dotted Python module paths to slash form so the suffix
    # match treats both ``tools.docs`` and ``tools/docs`` identically.
    if "/" not in s:
        s = s.replace(".", "/")
    return s.strip("/")


def _path_endswith_suffix(file_path: str, candidate: str) -> bool:
    """Path-component-aware endswith.

    Returns ``True`` iff ``candidate`` (treated as a forward-slashed
    path-suffix) lines up with ``file_path``'s trailing path components.
    Tolerates a trailing source extension, separator differences, and
    package indirection through ``__init__.py``.

    Examples::

        ("/abs/repo/src/tools/add.ts",       "tools/add")     -> True
        ("/abs/repo/src/utils/add.ts",       "tools/add")     -> False
        ("/abs/repo/src/tools/add/__init__.py", "tools/add")  -> True
    """
    if not candidate:
        return False
    p = file_path.replace("\\", "/")
    p = _strip_source_extension(p)
    cand = candidate.replace("\\", "/").strip("/")
    if not cand:
        return False
    if p == cand or p.endswith("/" + cand):
        return True
    # ``foo/__init__`` matches an import targeting ``foo`` (Python pkg).
    if p.endswith("/" + cand + "/__init__"):
        return True
    return False


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
        a.start_byte == b.start_byte and a.end_byte == b.end_byte and a.type == b.type
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
    "kotlin": ("io.modelcontextprotocol",),
    "java": (
        "io.modelcontextprotocol",
        "org.springframework.ai",
    ),
    "c_sharp": ("modelcontextprotocol",),
    "php": (
        "phpmcp",
        "modelcontextprotocol",
    ),
    "ruby": ("mcp",),
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
            namespace = ns_match.group(1).rstrip(":\\.") if ns_match else ""

            cap = allowed.get(ident)
            if cap is None:
                continue

            # Generic leaves (``Tool`` / ``Prompt`` / ``Resource``) need a
            # trusted namespace. Vendor-prefixed leaves (``McpServerTool``)
            # are accepted unconditionally because they only collide with
            # MCP itself.
            is_generic = ident in {
                "Tool",
                "Prompt",
                "Resource",
                "tool",
                "prompt",
                "resource",
            }
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
