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

"""MCP capability detection — separated from generic AST extraction.

The static analysis layer used to do two unrelated jobs in one file:

    1. Extract every function context + dataflow / taint information
       (``NativeAnalyzer`` in ``native_analyzer.py``).
    2. Detect MCP-annotated capabilities (tools, prompts, resources)
       across all supported languages.

Job (2) was roughly 1,700 lines, lived as private methods on
``NativeAnalyzer``, and operated at a higher level of abstraction than
the rest of the file. This module hosts the entire capability-detection
pipeline as a standalone class so it can be reviewed, tested, and
evolved independently.

``CapabilityDetector`` composes a ``NativeAnalyzer`` rather than
inheriting from it: the detector reuses generic AST/Tree-sitter
helpers (``_ts_extract_imports``, ``_ts_extract_function_context``,
``_py_extract_function``, …) via a thin ``__getattr__`` delegation,
and exposes only capability-shaped output.

Public surface:

* :class:`CapabilityRecord` — lightweight dataclass describing one
  detected capability.
* :class:`CapabilityDetector` — orchestrates Pass 1 (function-attached
  annotations) and Pass 2 (call-site registrations), with cross-file
  resolution support.

Backward compatibility: ``NativeAnalyzer.extract_mcp_capability_contexts``
remains as a deprecation shim that forwards to this module.
"""

import ast
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple, Union, TYPE_CHECKING

from .context_extractor import FunctionContext

if TYPE_CHECKING:
    from tree_sitter import Node
    from .native_analyzer import NativeAnalyzer

# Tree-sitter at runtime: imported here so ``Language`` / ``Parser`` are
# usable from ``CapabilityDetector.detect`` without re-importing inside
# the hot path.
from tree_sitter import Language, Parser, QueryCursor

from .capability_queries import QueryBundle, get_bundle

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
    ".py", ".pyi", ".pyx",
    ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",
    ".go", ".rb", ".rs",
    ".kt", ".kts",
    ".java", ".cs", ".php", ".m",
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





# =============================================================================
# CapabilityRecord — public output type
# =============================================================================


@dataclass
class CapabilityRecord:
    """A single MCP capability detected in source code.

    ``CapabilityDetector.detect`` returns a list of these. The current
    behavioral analyzer pipeline still consumes ``FunctionContext``
    objects, so ``CapabilityDetector.extract_mcp_capability_contexts``
    is provided as a backward-compatible adapter.
    """

    capability: str  # "tool" | "prompt" | "resource"
    name: Optional[str] = None  # registered MCP name (e.g. "add")
    handler_name: Optional[str] = None  # symbol name of the resolved handler
    source_kind: str = "annotation"  # "annotation" | "registration" | "registration.unresolved" | ...
    source_file: Optional[str] = None  # cross-file definition path, if any
    function_context: Optional[FunctionContext] = None  # populated when the body is locally available


# =============================================================================
# CapabilityDetector — orchestrates Pass 1 + Pass 2 detection
# =============================================================================


class CapabilityDetector:
    """Detect MCP-annotated capabilities in a single source file.

    The detector composes a :class:`NativeAnalyzer` for low-level AST /
    Tree-sitter helpers (parsing, function indexing, taint primitives)
    and adds the MCP-specific classification on top:

    Pass 1 — function-attached annotation/attribute/macro detection
    (``@mcp.tool``, ``@McpTool``, ``[McpServerTool]``, ``#[tool]``,
    ``# @tool``).

    Pass 2 — SDK call-site registration detection
    (``server.tool('name', schema, handler)``, ``mcp.AddTool(...)``,
    ``server.addTool(...) { req -> }``, ``setRequestHandler``).

    Construction is cheap; ``detect()`` is the primary public entry
    point. ``extract_mcp_capability_contexts(...)`` exists for
    backward-compatible callers that still expect ``FunctionContext``
    output.
    """

    def __init__(self, analyzer: "NativeAnalyzer"):
        """Bind a detector to an existing ``NativeAnalyzer`` instance.

        ``analyzer`` provides the parsed source, language detection,
        Tree-sitter helpers, and per-function context extraction. The
        detector adds the MCP-specific classification layer.
        """
        self._analyzer = analyzer

    def __getattr__(self, name: str) -> Any:
        """Delegate unknown attribute access to the underlying analyzer.

        Lets the migrated methods reference ``self.language``,
        ``self.source_bytes``, ``self._ts_get_node_text``,
        ``self._py_extract_function`` etc. without surgical renames.
        Only invoked when normal attribute lookup fails on the
        detector, so methods/constants defined on the detector
        shadow the analyzer naturally.
        """
        analyzer = object.__getattribute__(self, "_analyzer")
        return getattr(analyzer, name)

    # ------------------------------------------------------------------
    # Public detection entry points
    # ------------------------------------------------------------------

    def detect(
        self,
        cross_file_analyzer: Optional[Any] = None,
    ) -> List[CapabilityRecord]:
        """Return :class:`CapabilityRecord` objects for the detected capabilities.

        The lightweight record list is preferred for new callers — it
        keeps the detector decoupled from ``FunctionContext`` plumbing
        and lets consumers pull only the fields they need.
        """
        contexts = self.extract_mcp_capability_contexts(
            cross_file_analyzer=cross_file_analyzer
        )
        records: List[CapabilityRecord] = []
        for ctx in contexts:
            cap = _capability_from_decorator_types(ctx.decorator_types)
            if cap is None:
                continue
            source_kind = _source_kind_from_decorator_types(ctx.decorator_types)
            records.append(
                CapabilityRecord(
                    capability=cap,
                    name=ctx.name if ctx.name and ctx.name != "<unresolved>" else None,
                    handler_name=ctx.name if ctx.name and ctx.name != "<unresolved>" else None,
                    source_kind=source_kind,
                    source_file=getattr(ctx, "source_file", None),
                    function_context=ctx,
                )
            )
        return records

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

        # Lazy import to break the circular dependency with
        # ``native_analyzer`` (which re-exports from this module at
        # top level for backward compatibility).
        from .native_analyzer import _get_language_module

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

        # Build an import-target map once per extract call: cross-file
        # resolution prefers entries whose defining file path matches
        # one of the calling file's import targets, killing the
        # "wrong same-named function in node_modules wins" failure mode.
        import_target_map = self._build_import_target_map(
            imports, current_file=str(self.file_path) if self.file_path else None
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
            # up. The resolver prefers matches whose path lines up with
            # one of the calling file's import targets so a sibling
            # ``tests/fixtures/add.ts`` defining the same name doesn't
            # win the suffix race.
            cross_file_match: Optional["tuple[str, Any]"] = None
            if handler_node is None and handler_name and cross_file_analyzer is not None:
                cross_file_match = self._resolve_cross_file_handler(
                    handler_name,
                    cross_file_analyzer,
                    target_module_paths=import_target_map.get(handler_name),
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

    def _py_collect_import_targets(
        self, stmt: str, out: Dict[str, List[str]]
    ) -> None:
        """Populate ``out`` from one Python import statement."""
        # ``from <module> import X [as Y], ...``
        m = _re.match(r"^from\s+(\S+)\s+import\s+(.+?)\s*$", stmt)
        if m:
            module = _normalize_module_specifier(m.group(1))
            for piece in m.group(2).split(","):
                piece = piece.strip().rstrip(")").lstrip("(")
                if not piece or piece == "*":
                    continue
                parts = _re.split(r"\s+as\s+", piece, maxsplit=1)
                orig = parts[0].strip()
                bound = parts[1].strip() if len(parts) > 1 else orig
                if not bound:
                    continue
                # ``orig`` could either be a function within ``module``
                # or a submodule of ``module`` (when used like
                # ``from .tools import docs`` to bind a module). Record
                # both candidates so the resolver can pick whichever
                # actually exists in the call graph.
                if module:
                    out.setdefault(bound, []).append(module)
                    out[bound].append(f"{module}/{orig}")
                else:
                    out.setdefault(bound, []).append(orig)
            return
        # ``import M [as N]`` or ``import M.sub``
        m = _re.match(r"^import\s+([\w\.]+)(?:\s+as\s+(\w+))?\s*$", stmt)
        if m:
            full = m.group(1)
            alias = m.group(2)
            bound = alias or full.split(".", 1)[0]
            out.setdefault(bound, []).append(_normalize_module_specifier(full))

    def _ts_collect_import_targets(
        self, stmt: str, out: Dict[str, List[str]]
    ) -> None:
        """Populate ``out`` from one TS/JS import statement."""
        # ``import <clause> from "<module>"``
        m = _re.match(
            r"""^import\s+(.*?)\s+from\s+['"]([^'"]+)['"]""",
            stmt,
        )
        if m:
            clause = m.group(1).strip()
            path = _normalize_module_specifier(m.group(2))
            if not path:
                return
            # ``import * as ns from "..."``
            ns = _re.match(r"^\*\s+as\s+(\w+)$", clause)
            if ns:
                out.setdefault(ns.group(1), []).append(path)
                return
            # ``import default, { a, b as c } from "..."`` — split
            # default-import + named-import block.
            if not clause.startswith("{"):
                head, _, rest = clause.partition(",")
                head = head.strip()
                if head:
                    out.setdefault(head, []).append(path)
                clause = rest.strip()
            m2 = _re.match(r"^\{(.*)\}$", clause, _re.DOTALL)
            if m2:
                for piece in m2.group(1).split(","):
                    piece = piece.strip()
                    if not piece:
                        continue
                    parts = _re.split(r"\s+as\s+", piece, maxsplit=1)
                    bound = (
                        parts[1].strip()
                        if len(parts) > 1
                        else parts[0].strip()
                    )
                    if bound:
                        out.setdefault(bound, []).append(path)
            return
        # ``const x = require("./tools/add")`` — best-effort.
        m = _re.match(
            r"""^(?:const|let|var)\s+(\w+)\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)""",
            stmt,
        )
        if m:
            bound = m.group(1)
            path = _normalize_module_specifier(m.group(2))
            if path:
                out.setdefault(bound, []).append(path)

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

    # -------------------------------------------------------------------------
    # Helpers for the new lazy/single-pass paths
    # -------------------------------------------------------------------------

    # ``_has_mcp_markers`` lives on :class:`NativeAnalyzer` so the
    # behavioral code analyzer's directory-level prefilter can reuse it
    # and the cache stays on the long-lived analyzer instance. The
    # detector picks it up via ``__getattr__`` delegation.

    def _py_extract_capability_contexts(
        self,
        *,
        cross_file_analyzer: Any = None,
    ) -> List[FunctionContext]:
        """Lazy Python capability extraction (Gap 5 + Gap 8).

        The previous implementation called ``extract_all_function_contexts``
        which forced a full ForwardDataflowAnalysis pass on every helper
        function in the file *before* filtering them out — defeating the
        purpose of the capability extractor on helper-heavy modules.

        The new path:

          1. Run the byte-level prefilter once. If the file has no MCP
             markers, return ``[]`` without parsing.
          2. ``ast.parse`` once.
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

        Failure modes:

        - The byte-level prefilter rejects files with no MCP markers
          (returns ``[]`` immediately).
        - ``ast.parse`` failures on unparseable Python return ``[]``.
        - Per-function extraction failures (in
          ``_py_extract_function`` or the programmatic-registration
          handler resolver) are logged at ``DEBUG`` and skipped
          individually; one bad function does not abort the whole pass.

        There is intentionally no outer try/except that re-runs the
        legacy ``extract_all_function_contexts`` path. An earlier draft
        of this docstring claimed otherwise — that promise was removed
        because falling back to the legacy walker would re-introduce
        the helper-bloat regression this method was written to fix
        (every plain helper would be sent to dataflow analysis).
        """
        if not self._has_mcp_markers():
            return []
        try:
            tree = ast.parse(self.source_code, filename=str(self.file_path))
        except SyntaxError:
            return []

        module_imports = self._py_extract_imports(tree)
        wrapper_decorators = self._py_collect_wrapper_decorators(tree)
        # Identify trusted MCP server-instance names so
        # ``@<receiver>.tool`` only classifies when ``<receiver>``
        # actually binds to an MCP SDK instance.
        mcp_instances = self._py_collect_mcp_instances(tree, module_imports)

        # Build the import-target map once per call so the cross-file
        # resolver can disambiguate same-named functions via the
        # calling file's own import paths.
        import_target_map = self._build_import_target_map(
            module_imports,
            current_file=str(self.file_path) if self.file_path else None,
        )

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
                decorator_names,
                wrapper_decorators,
                trusted_receivers=mcp_instances,
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
        # calls, etc.) become cross-file or unresolved-handler stubs so
        # the LLM / report layer still sees a capability was
        # registered.
        for (
            handler_node,
            label,
            cap_kind,
            cross_file_path,
        ) in self._py_iter_programmatic_registrations(
            tree,
            functions_by_name=functions_by_name,
            class_methods=class_methods,
            cross_file_analyzer=cross_file_analyzer,
            import_target_map=import_target_map,
        ):
            if handler_node is None and cross_file_path is not None:
                # Cross-file resolution succeeded — emit a
                # ``registration.cross_file`` stub like the TS path so
                # consumers can show the user where the handler lives.
                stub_key = (("crossfile", cross_file_path, label), cap_kind)
                if stub_key in seen:
                    continue
                seen.add(stub_key)
                self._append_unresolved_capability(
                    contexts,
                    capability=cap_kind,
                    registered_name=label,
                    source_kind="registration.cross_file",
                    handler_name_hint=label,
                    source_file=cross_file_path,
                )
                continue
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
        *,
        trusted_receivers: Optional[Set[str]] = None,
    ) -> Optional[str]:
        """Return the canonical capability kind for ``decorator_names``.

        Accepts both built-in MCP decorators (FastMCP / low-level
        Server) and locally-defined wrapper decorators discovered via
        ``_py_collect_wrapper_decorators``.

        Receiver verification (Gap 4 parity):
        when ``trusted_receivers`` is non-empty, decorators of the form
        ``@<receiver>.<method>`` only classify as MCP if ``<receiver>``
        is a known MCP server instance bound in this file. Bare
        decorators (``@tool``, no dot) are always accepted because they
        can only have come from a direct symbol import. When the
        receiver set is empty (provenance pass found nothing) we apply
        the same "loose if empty" tradeoff as TS so unusual import
        patterns still work.
        """
        for name in decorator_names or []:
            kind = _python_decorator_capability(name)
            if kind is not None:
                if trusted_receivers and "." in name:
                    receiver = name.rsplit(".", 1)[0].strip()
                    # Strip any call-args so ``foo(args).tool`` reduces
                    # to ``foo`` for receiver lookup.
                    receiver_root = receiver.split(".", 1)[0].split("(", 1)[0]
                    if receiver_root not in trusted_receivers:
                        # Receiver isn't a known MCP instance; reject
                        # this decorator and keep scanning the list —
                        # another decorator on the same function may
                        # still be a valid MCP capability.
                        continue
                return kind
            bare = name.rsplit(".", 1)[-1].split("(", 1)[0].strip()
            wrapped = wrapper_decorators.get(bare)
            if wrapped:
                return wrapped
        return None

    def _py_collect_mcp_instances(
        self, tree: ast.AST, module_imports: List[str]
    ) -> Set[str]:
        """Identify Python local names bound to an MCP server instance.

        AST-based mirror of :meth:`_collect_mcp_instances` (which runs
        on tree-sitter): the lazy Python path doesn't have a tree-sitter
        tree available, so we walk ``ast`` instead. Recognized
        provenance shapes::

            mcp = FastMCP("demo")                          # Assign
            server = Server()                              # Assign
            mcp = mcp.server.fastmcp.FastMCP(...)          # Assign
            mcp: FastMCP = ...                             # AnnAssign
            def f(server: Server): ...                     # parameter
            class S:
                def m(self, server: FastMCP): ...          # parameter

        SDK class names are sourced from this file's ``from <mcp-sdk>
        import X [as Y]`` statements (so locally-renamed classes still
        match) plus the global ``_MCP_KNOWN_SERVER_CLASSES`` allow-list
        as a backstop for unusual import shapes.

        Returns the union of bound instance names and SDK package
        aliases. Returns an empty set when no SDK import is detected so
        the caller can fall back to loose receiver matching rather than
        silently dropping registrations.
        """
        prefixes = _MCP_SDK_MODULE_PREFIXES.get("python", ())
        if not prefixes:
            return set()

        sdk_classes: Set[str] = set()
        sdk_aliases: Set[str] = set()
        for stmt in module_imports or []:
            stmt_lc = stmt.lower()
            if not any(p in stmt_lc for p in prefixes):
                continue
            # ``from <module> import X [as Y], Z, ...``
            m = _re.match(r"^\s*from\s+([\w\.]+)\s+import\s+(.+)$", stmt)
            if m:
                for sym in m.group(2).split(","):
                    sym = sym.strip()
                    parts = _re.split(r"\s+as\s+", sym, maxsplit=1)
                    bound = (
                        parts[1].strip()
                        if len(parts) > 1
                        else parts[0].strip()
                    )
                    if not bound:
                        continue
                    # Heuristic: PascalCase = class, snake_case / lower
                    # = module alias. Cheap and accurate for SDK code.
                    if bound[:1].isupper():
                        sdk_classes.add(bound)
                    else:
                        sdk_aliases.add(bound)
                continue
            # ``import <module> [as alias]`` — bind the alias.
            m = _re.match(r"^\s*import\s+([\w\.]+)(?:\s+as\s+(\w+))?\s*$", stmt)
            if m:
                full = m.group(1)
                alias = m.group(2)
                bound = alias or full.split(".", 1)[0]
                sdk_aliases.add(bound)

        # Backstop allow-list: even if the import line was unusual, a
        # call to ``FastMCP(...)`` / ``Server(...)`` should bind a
        # trusted receiver. Same names tree-sitter uses.
        sdk_classes.update(_MCP_KNOWN_SERVER_CLASSES)

        trusted: Set[str] = set(sdk_aliases)

        def _matches_sdk_class(call_or_attr: ast.AST) -> bool:
            """Return True if the node names an MCP SDK class."""
            full = ""
            if isinstance(call_or_attr, ast.Call):
                full = self._py_get_node_name(call_or_attr.func)
            elif isinstance(call_or_attr, (ast.Attribute, ast.Name)):
                full = self._py_get_node_name(call_or_attr)
            if not full:
                return False
            leaf = full.rsplit(".", 1)[-1].split("(", 1)[0].strip()
            return leaf in sdk_classes

        for node in ast.walk(tree):
            # ``mcp = FastMCP("demo")``
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                if _matches_sdk_class(node.value):
                    for tgt in node.targets:
                        if isinstance(tgt, ast.Name):
                            trusted.add(tgt.id)
            # ``mcp: FastMCP = FastMCP(...)`` or just the annotation.
            if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                ann_text = self._py_unparse_safe(node.annotation)
                leaf = ann_text.rsplit(".", 1)[-1] if ann_text else ""
                if leaf in sdk_classes:
                    trusted.add(node.target.id)
                if isinstance(node.value, ast.Call) and _matches_sdk_class(node.value):
                    trusted.add(node.target.id)
            # Function-parameter type annotations:
            # ``def f(server: FastMCP): ...``
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                params: List[ast.arg] = []
                params.extend(node.args.args or [])
                params.extend(node.args.kwonlyargs or [])
                if node.args.vararg is not None:
                    params.append(node.args.vararg)
                if node.args.kwarg is not None:
                    params.append(node.args.kwarg)
                for arg in params:
                    if arg.annotation is None:
                        continue
                    ann_text = self._py_unparse_safe(arg.annotation)
                    leaf = ann_text.rsplit(".", 1)[-1] if ann_text else ""
                    if leaf in sdk_classes:
                        trusted.add(arg.arg)

        return trusted

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
        *,
        cross_file_analyzer: Any = None,
        import_target_map: Optional[Dict[str, List[str]]] = None,
    ) -> "tuple[Optional[Union[ast.FunctionDef, ast.AsyncFunctionDef]], str, Optional[str]]":
        """Resolve a handler expression at a registration call site.

        Returns ``(function_node_or_None, human_label, cross_file_path_or_None)``.

        * ``function_node`` is non-None when the handler resolves to a
          local AST node we can run dataflow on.
        * ``cross_file_path`` is non-None when in-file resolution failed
          but the cross-file call graph located the defining file. The
          caller should emit a ``registration.cross_file`` stub
          pointing at this path (mirroring the TS behavior).
        * Both ``None`` means the handler is genuinely unresolved
          (lambda, factory call, dynamic attr, etc.) — callers emit a
          plain unresolved stub so downstream consumers still see the
          capability was registered.
        """
        # Local lookup helpers ------------------------------------------------
        def _crossfile(name: str) -> Optional[str]:
            if cross_file_analyzer is None or not name:
                return None
            targets = (
                import_target_map.get(name) if import_target_map else None
            )
            try:
                match = self._resolve_cross_file_handler(
                    name,
                    cross_file_analyzer,
                    target_module_paths=targets,
                )
            except Exception:
                return None
            if match is None:
                return None
            return match[0]

        if isinstance(handler, ast.Name):
            local = functions_by_name.get(handler.id)
            if local is not None:
                return local, handler.id, None
            # Bare name missed in this file — try the cross-file graph.
            cross_file_path = _crossfile(handler.id)
            return None, handler.id, cross_file_path

        if isinstance(handler, ast.Attribute) and isinstance(
            handler.value, ast.Name
        ):
            base = handler.value.id
            attr = handler.attr
            if base in ("self", "cls") and enclosing_cls:
                node = class_methods.get(enclosing_cls, {}).get(attr)
                return node, f"{enclosing_cls}.{attr}", None
            # ``<module>.<name>`` — look up ``name`` in the call
            # graph, restricted to entries whose path lines up with
            # whatever ``<module>`` was bound to in this file's
            # imports. Without the import-map filter we'd suffix-match
            # any ``::<name>`` and possibly analyze the wrong file.
            target_paths: Optional[List[str]] = None
            if import_target_map:
                target_paths = import_target_map.get(base) or None
            cross_file_path: Optional[str] = None
            if cross_file_analyzer is not None and target_paths is not None:
                try:
                    match = self._resolve_cross_file_handler(
                        attr,
                        cross_file_analyzer,
                        target_module_paths=target_paths,
                    )
                except Exception:
                    match = None
                if match is not None:
                    cross_file_path = match[0]
            return None, f"{base}.{attr}", cross_file_path

        # Lambda, factory call, subscript, etc. — surface as unresolved
        # so the LLM still sees that something was registered here.
        return None, "<unresolved>", None

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
        *,
        cross_file_analyzer: Any = None,
        import_target_map: Optional[Dict[str, List[str]]] = None,
    ) -> List[
        "tuple[Optional[Union[ast.FunctionDef, ast.AsyncFunctionDef]], str, str, Optional[str]]"
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

        Returns a list of
        ``(handler_node_or_None, label, capability, cross_file_path_or_None)``
        tuples.

        * ``handler_node`` non-None — local node, run dataflow on it.
        * ``handler_node`` None and ``cross_file_path`` non-None —
          handler resolved into another file via the call graph (Review
          #6); callers emit a ``registration.cross_file`` stub
          referencing that path.
        * Both None — genuinely unresolved (lambda, factory call,
          dynamic attribute, etc.); callers emit a plain unresolved
          stub so downstream consumers still see a registration.
        """
        functions_by_name = functions_by_name or {}
        class_methods = class_methods or {}

        out: List[
            "tuple[Optional[Union[ast.FunctionDef, ast.AsyncFunctionDef]], str, str, Optional[str]]"
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

            handler_node, label, cross_file_path = self._py_resolve_handler_expr(
                handler_expr,
                enclosing_cls,
                class_methods,
                functions_by_name,
                cross_file_analyzer=cross_file_analyzer,
                import_target_map=import_target_map,
            )
            out.append((handler_node, label, kind, cross_file_path))

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

        Two implementation paths share the cache:

        * **Query-backed**: when a ``functions.scm`` query is shipped
          for the active language, iterate matches from the query and
          call :py:meth:`_ts_collect_function_annotations` on each
          captured ``@func_def`` node. The per-function annotation
          walk stays imperative because tree-sitter queries don't
          model "preceding sibling" in a way that's portable across
          all grammars (Rust ``attribute_item``, Ruby ``# @tool``
          comment, etc.) — the imperative collector already handles
          those uniformly.
        * **Imperative**: fallback for languages without a ``.scm``
          functions query (today: just Python).

        Both paths produce byte-for-byte identical output for any node
        the imperative walker would have visited.
        """
        cache_attr = "_annotation_index_cache"
        cached: Optional[Dict[int, List[str]]] = None
        cache_key = (id(root), self.language)
        # Cache on the underlying analyzer (see ``_ts_build_function_index``).
        analyzer = self._analyzer
        store = getattr(analyzer, cache_attr, None)
        if store is None:
            store = {}
            setattr(analyzer, cache_attr, store)
        cached = store.get(cache_key)
        if cached is not None:
            return cached

        bundle = get_bundle(self.language)
        if bundle is not None and bundle.functions is not None:
            index = self._ts_build_annotation_index_q(
                root, func_types, bundle.functions
            )
            store[cache_key] = index
            return index

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

    def _ts_build_annotation_index_q(
        self,
        root: "Node",
        func_types: Set[str],
        query: Any,
    ) -> Dict[int, List[str]]:
        """Query-backed equivalent of the imperative annotation walk.

        Uses ``functions.scm`` to enumerate every function-shaped node
        in the tree, then calls
        :py:meth:`_ts_collect_function_annotations` on each match. The
        per-function annotation collector is reused unchanged — it
        already handles every annotation shape across supported
        languages (Rust sibling ``attribute_item``, Ruby leading
        ``comment``, Java/Spring AI nested ``modifiers``, C#/PHP
        ``attribute_list``, …) — so behaviour stays identical to the
        imperative path on a per-function basis.

        ``func_types`` is consulted as a sanity filter so we never
        collect annotations for a node whose type isn't a recognized
        function shape (defends against ``.scm`` patterns drifting
        from the canonical set in :py:attr:`NativeAnalyzer.FUNCTION_NODE_TYPES`).
        ``_TS_NON_FUNCTION_NODE_TYPES`` is honoured for the same
        reason — the imperative path skips ``impl_item`` and the
        query path must too.
        """
        index: Dict[int, List[str]] = {}
        seen: Set[int] = set()
        cursor = QueryCursor(query)
        for _pat_idx, captures in cursor.matches(root):
            def_nodes = captures.get("func_def")
            if not def_nodes:
                continue
            fn_node = def_nodes[0]
            if (
                fn_node.type not in func_types
                or fn_node.type in _TS_NON_FUNCTION_NODE_TYPES
            ):
                continue
            # Two patterns may legitimately match the same node (e.g.
            # Kotlin's lambda/anonymous-function fallbacks), so we
            # de-dup by start_byte — the same key the imperative path
            # uses as the dictionary key.
            if fn_node.start_byte in seen:
                continue
            seen.add(fn_node.start_byte)
            annotations = self._ts_collect_function_annotations(fn_node)
            if annotations:
                index[fn_node.start_byte] = annotations
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

        Dispatches to the query-backed implementation when a compiled
        :class:`QueryBundle` is available for the active language; falls
        back to the imperative walker otherwise. The two paths are
        contract-equivalent — same return shape, same per-language
        quirks honoured (Kotlin trailing lambdas, low-level schema
        capability mapping, …) — so callers don't need to know which
        path ran.

        See :py:meth:`_ts_find_mcp_registrations_imperative` for the
        full behavioural description; the query path is documented at
        :py:meth:`_ts_find_mcp_registrations_q`.
        """
        bundle = get_bundle(self.language)
        if bundle is not None and bundle.registrations is not None:
            return self._ts_find_mcp_registrations_q(
                root, trusted_receivers, bundle
            )
        return self._ts_find_mcp_registrations_imperative(
            root, trusted_receivers
        )

    def _ts_find_mcp_registrations_imperative(
        self,
        root: "Node",
        trusted_receivers: Optional[Set[str]] = None,
    ) -> List[Dict[str, Any]]:
        """Imperative tree walk for capability registrations.

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

        Kept on the class because languages without query coverage
        (Kotlin, Java, C#, Rust, PHP, Ruby) still rely on it, and so
        we can A/B against the query-backed path during validation.
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

    # ------------------------------------------------------------------
    # Query-backed registration finders.
    #
    # The ``_q`` variants delegate the *pattern matching* to a compiled
    # tree-sitter query and keep the *semantic* parts (receiver-trust
    # check, argument shape parsing, Kotlin trailing-lambda fixup,
    # low-level schema → capability mapping) in Python. Result shape is
    # identical to the imperative path so the dispatcher in
    # :py:meth:`_ts_find_mcp_registrations` can swap between them
    # transparently.
    # ------------------------------------------------------------------
    def _ts_find_mcp_registrations_q(
        self,
        root: "Node",
        trusted_receivers: Optional[Set[str]],
        bundle: "QueryBundle",
    ) -> List[Dict[str, Any]]:
        """Query-backed equivalent of :py:meth:`_ts_find_mcp_registrations_imperative`.

        Two queries run in succession when both are present:

        * ``bundle.registrations`` — high-level methods (``tool``,
          ``registerTool``, …). Capability is derived from the method
          name via :func:`_normalize_capability` and template subtype
          via :func:`_classify_template_subtype`.
        * ``bundle.low_level``    — TS low-level Server's
          ``setRequestHandler``. Capability is derived from the leading
          ``*RequestSchema`` argument via
          :py:meth:`_ts_low_level_capability`.

        For every accepted call we still call
        :py:meth:`_ts_receiver_is_trusted`, so silent registration
        leaks from unrelated DSLs that happen to expose ``.tool(...)``
        cannot slip through just because the call shape matches.
        """
        trusted_receivers = trusted_receivers or set()
        registrations: List[Dict[str, Any]] = []

        if bundle.registrations is not None:
            self._collect_q_registrations(
                root,
                bundle.registrations,
                trusted_receivers,
                registrations,
                low_level=False,
            )
        if bundle.low_level is not None:
            self._collect_q_registrations(
                root,
                bundle.low_level,
                trusted_receivers,
                registrations,
                low_level=True,
            )
        return registrations

    def _collect_q_registrations(
        self,
        root: "Node",
        query: Any,
        trusted_receivers: Set[str],
        out: List[Dict[str, Any]],
        *,
        low_level: bool,
    ) -> None:
        """Run ``query`` over ``root`` and emit registration dicts.

        The semantic logic (trust check, argument parsing, low-level
        schema mapping, trailing-lambda lookup) is shared with the
        imperative walker via the existing private helpers; this method
        just translates the query's match dicts into calls into those
        helpers.

        Some grammars (notably Kotlin) need TWO patterns to cover both
        the bare and trailing-lambda registration shapes: the inner
        ``server.addTool(args)`` call matches pattern 1, and the outer
        ``addTool(args){lambda}`` wrapper matches pattern 2. Both
        capture ``@call`` as the same inner-call node, so we merge
        per-call by ``(start_byte, end_byte)`` and prefer the merged
        match that carries a ``@lambda`` capture — that's what gives
        the Kotlin trailing lambda its handler.
        """
        cursor = QueryCursor(query)

        # First pass: group matches by the inner-call signature so
        # duplicate hits (Kotlin's bare-vs-wrapped patterns) collapse
        # into one entry that carries the union of captures.
        #
        # ``ordered`` preserves source-discovery order so the output
        # stays deterministic. ``index`` maps a call signature to its
        # position in ``ordered`` so duplicates merge in-place. We
        # only copy ``captures`` once a duplicate is seen — non-Kotlin
        # languages take the fast path and never copy. ``copied_at``
        # tracks which entries we already copied so the merge step
        # doesn't accidentally clone twice if a third match arrives.
        ordered: List[Tuple[Tuple[int, int], Dict[str, List["Node"]]]] = []
        index: Dict[Tuple[int, int], int] = {}
        copied_at: Set[int] = set()
        for _pat_idx, captures in cursor.matches(root):
            call_nodes = captures.get("call")
            method_nodes = captures.get("method")
            if not call_nodes or not method_nodes:
                continue
            call_node = call_nodes[0]
            sig = (call_node.start_byte, call_node.end_byte)
            existing_idx = index.get(sig)
            if existing_idx is None:
                index[sig] = len(ordered)
                ordered.append((sig, captures))
                continue
            # Merge: copy-on-first-merge so we don't mutate tree-
            # sitter's match dict. ``setdefault`` makes first-seen win
            # for stable scalar fields; the new match contributes
            # ``@lambda`` (and any other key the original lacked).
            prev_sig, prev_caps = ordered[existing_idx]
            if existing_idx not in copied_at:
                prev_caps = dict(prev_caps)
                ordered[existing_idx] = (prev_sig, prev_caps)
                copied_at.add(existing_idx)
            for key, nodes in captures.items():
                prev_caps.setdefault(key, nodes)

        for sig, captures in sorted(ordered, key=lambda item: item[0]):
            call_nodes = captures.get("call") or []
            method_nodes = captures.get("method") or []
            args_nodes = captures.get("args") or []
            lambda_nodes = captures.get("lambda") or []
            if not call_nodes or not method_nodes:
                continue
            call_node = call_nodes[0]
            method_text = self._ts_get_node_text(method_nodes[0])
            method_lc = method_text.lower()

            # Receiver-trust gate: drop unrelated DSLs that expose a
            # method name we recognize. The check is identical to the
            # imperative path.
            if not self._ts_receiver_is_trusted(
                call_node, method_lc, trusted_receivers
            ):
                continue

            args_node = args_nodes[0] if args_nodes else None

            if low_level:
                ll_cap = self._ts_low_level_capability(args_node)
                if ll_cap is None:
                    continue
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
                    reg = {
                        "capability": _normalize_capability(method_lc),
                        "name": None,
                        "handler_node": None,
                        "handler_name": None,
                    }
                reg["template_subtype"] = _classify_template_subtype(method_lc)

            # Trailing-lambda lookup. Three sources, in priority:
            #   (1) explicit ``@lambda`` capture (Kotlin's wrapped
            #       trailing-lambda pattern surfaces it directly);
            #   (2) the call's own children (TS/JS arrow callbacks
            #       that the args parser missed);
            #   (3) the parent's siblings — the *imperative* Kotlin
            #       walker uses this fallback when older grammar
            #       versions place the trailing lambda outside the
            #       outer call_expression. Keeping it here means the
            #       query path matches imperative behaviour byte-for-
            #       byte even on grammar-version drift.
            if reg.get("handler_node") is None:
                for ln in lambda_nodes:
                    unwrapped = self._ts_unwrap_trailing_lambda(ln)
                    if unwrapped is not None:
                        reg["handler_node"] = unwrapped
                        break
            if reg.get("handler_node") is None:
                for child in call_node.children:
                    lambda_node = self._ts_unwrap_trailing_lambda(child)
                    if lambda_node is not None:
                        reg["handler_node"] = lambda_node
                        break
            if reg.get("handler_node") is None:
                parent = call_node.parent
                if parent is not None:
                    for sibling in parent.children:
                        if _is_same_ts_node(sibling, call_node):
                            continue
                        lambda_node = self._ts_unwrap_trailing_lambda(sibling)
                        if lambda_node is not None:
                            reg["handler_node"] = lambda_node
                            break

            if reg.get("name") is None and args_node is not None:
                reg["name"] = self._ts_first_string_literal_in_args(args_node)

            if (
                reg.get("handler_node") is not None
                or reg.get("handler_name") is not None
            ):
                out.append(reg)

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
        # The query-backed path covers the JS/TS/Go binding shapes; the
        # imperative path retains parameter-type and Python/Kotlin
        # ``assignment`` shapes that aren't expressible with the query
        # bundles we ship today. Languages that don't have a query
        # bundle still go through the imperative path entirely.
        bundle = get_bundle(self.language)
        if bundle is not None and bundle.instantiations is not None:
            self._collect_mcp_instances_q(
                root, bundle.instantiations, sdk_classes, sdk_aliases, trusted
            )
            # Parameter types and Python/Kotlin ``assignment`` shapes
            # aren't covered by the per-language query files yet, so we
            # still do a (cheap) imperative pass for those specific
            # cases. Restricted to non-Stage-2 node types so we don't
            # double-count the bindings the query already handled.
            self._collect_mcp_param_and_assignment_instances(
                root, sdk_classes, trusted
            )
        else:
            self._collect_mcp_instances_imperative(
                root, sdk_classes, sdk_aliases, trusted
            )

        return trusted

    # ------------------------------------------------------------------
    # Instance-binding collectors.
    #
    # ``_collect_mcp_instances_imperative`` is the original walker; the
    # ``_q`` variant uses ``instantiations.scm`` for the JS/TS/Go cases
    # and ``_collect_mcp_param_and_assignment_instances`` covers the
    # parameter-type / Python-style ``assignment`` shapes that aren't
    # in the query files (yet).
    # ------------------------------------------------------------------
    def _collect_mcp_instances_imperative(
        self,
        root: "Node",
        sdk_classes: Set[str],
        sdk_aliases: Set[str],
        trusted: Set[str],
    ) -> None:
        """Imperative AST walk that mirrors the legacy behaviour exactly."""

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

    def _collect_mcp_instances_q(
        self,
        root: "Node",
        query: Any,
        sdk_classes: Set[str],
        sdk_aliases: Set[str],
        trusted: Set[str],
    ) -> None:
        """Query-backed Stage 2 for the JS/TS/Go binding shapes.

        Matches each ``@target`` / ``@class`` capture pair from
        ``instantiations.scm`` and admits the binding when ``@class``
        matches one of the SDK classes (TS/JS) or the receiver of a
        factory call is a known SDK package alias (Go).
        """
        cursor = QueryCursor(query)
        for _pat_idx, captures in cursor.matches(root):
            target_nodes = captures.get("target")
            class_nodes = captures.get("class")
            if not target_nodes or not class_nodes:
                continue
            class_text = self._ts_get_node_text(class_nodes[0]).strip()
            if not class_text:
                continue

            # JS/TS: the captured @class is the leaf identifier of the
            # constructor / callee; admit if it's a known MCP server
            # class.
            if (
                class_text in sdk_classes
                or class_text.split(".")[-1] in sdk_classes
            ):
                trusted.add(self._ts_get_node_text(target_nodes[0]))
                continue

            # Go: the @receiver is the SDK package alias (e.g. ``mcp``)
            # and the @class is the factory method name. Admit when
            # the receiver is a known alias and the method name looks
            # like a server factory ("NewServer", "Server", …).
            receiver_nodes = captures.get("receiver")
            if not receiver_nodes:
                continue
            receiver_text = self._ts_get_node_text(receiver_nodes[0]).strip()
            if not receiver_text or receiver_text not in sdk_aliases:
                continue
            class_lc = class_text.lower()
            if "server" in class_lc or "newserver" in class_lc:
                trusted.add(self._ts_get_node_text(target_nodes[0]))

    def _collect_mcp_param_and_assignment_instances(
        self,
        root: "Node",
        sdk_classes: Set[str],
        trusted: Set[str],
    ) -> None:
        """Cover parameter-type and ``assignment`` instance bindings.

        These shapes (``def f(server: Server)``, Python's ``mcp =
        FastMCP("demo")``) aren't expressible cleanly in the per-
        language ``.scm`` files — Python doesn't have a query bundle
        and the typed-parameter forms vary across grammars — so we
        keep the small imperative walk for them. The walk skips the
        node types already handled by ``_collect_mcp_instances_q`` so
        results don't double-count.
        """

        def visit(node: "Node"):
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

            if node.type == "assignment":
                left = node.child_by_field_name("left")
                right = node.child_by_field_name("right")
                if left is not None and right is not None:
                    if self._ts_is_mcp_instantiation(right, sdk_classes):
                        trusted.add(self._ts_get_node_text(left))

            for child in node.children:
                visit(child)

        visit(root)

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

        Dispatches to a query-backed implementation when the active
        language has a compiled ``functions.scm`` bundle; falls back to
        the imperative walker otherwise. Cached per ``(file_root,
        language)`` on the underlying analyzer so repeated capability
        extraction on the same file (across multiple registrations,
        across both code paths) reuses the index.
        """
        cache_key = (id(root), self.language)
        analyzer = self._analyzer
        cached = getattr(analyzer, "_func_index_cache", None)
        if cached is None:
            cached = {}
            analyzer._func_index_cache = cached
        if cache_key in cached:
            return cached[cache_key]

        bundle = get_bundle(self.language)
        if bundle is not None and bundle.functions is not None:
            index = self._ts_build_function_index_q(
                root, func_types, bundle.functions
            )
        else:
            index = self._ts_build_function_index_imperative(root, func_types)

        cached[cache_key] = index
        return index

    def _ts_build_function_index_imperative(
        self, root: "Node", func_types: Set[str]
    ) -> Dict[str, "Node"]:
        """Imperative walk that records function/method/arrow defs.

        Records:
          * named function/method declarations (``function_declaration``,
            ``method_definition``, etc.),
          * arrow functions / function expressions assigned to a local
            via ``variable_declarator`` / ``assignment`` (``const fn = …``,
            ``fn = …``).

        Used as the fallback when no ``functions.scm`` query is shipped
        for the active language.
        """
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
        return index

    def _ts_build_function_index_q(
        self,
        root: "Node",
        func_types: Set[str],
        query: Any,
    ) -> Dict[str, "Node"]:
        """Query-backed equivalent of :py:meth:`_ts_build_function_index_imperative`.

        Each pattern in the ``functions.scm`` file emits a
        ``@func_name`` + ``@func_def`` capture pair; we just translate
        them into the same ``name -> Node`` dict shape. ``func_types``
        is consulted as a sanity filter so we never accidentally index
        a node whose type isn't a recognized function shape (defends
        against future ``.scm`` patterns drifting from the canonical
        type set).
        """
        index: Dict[str, "Node"] = {}
        cursor = QueryCursor(query)
        for _pat_idx, captures in cursor.matches(root):
            name_nodes = captures.get("func_name")
            def_nodes = captures.get("func_def")
            if not name_nodes or not def_nodes:
                continue
            def_node = def_nodes[0]
            if def_node.type not in func_types:
                continue
            name_text = self._ts_get_node_text(name_nodes[0])
            if not name_text:
                continue
            # ``setdefault`` mirrors the imperative walker's
            # first-write-wins behaviour, which matters when the same
            # symbol is rebound (we keep the first definition).
            index.setdefault(name_text, def_node)
        return index




# ---------------------------------------------------------------------------
# Helpers used by ``CapabilityDetector.detect`` to turn the
# ``FunctionContext`` output of the legacy entry point into the new
# lightweight ``CapabilityRecord`` shape.
# ---------------------------------------------------------------------------


def _capability_from_decorator_types(
    decorator_types: Optional[List[str]],
) -> Optional[str]:
    """Extract the capability kind from a context's decorator tags.

    Two tag shapes can appear:

    * Python (FastMCP / low-level Server) emits the raw decorator name
      as captured by AST extraction, e.g. ``mcp.tool``,
      ``server.call_tool``, or a wrapper alias.
    * Tree-sitter pipelines emit a synthetic
      ``<source_kind>.<capability>`` marker tag (e.g.
      ``<annotation>.tool``) appended by ``_append_capability_context``.

    We probe the synthetic marker first because it carries explicit
    capability information; fall back to ``_python_decorator_capability``
    so Python contexts still classify cleanly.
    """
    if not decorator_types:
        return None
    for dec in decorator_types:
        if not dec or not dec.startswith("<"):
            continue
        kind = dec.rsplit(".", 1)[-1]
        if kind in ("tool", "prompt", "resource"):
            return kind
    for dec in decorator_types:
        cap = _python_decorator_capability(dec)
        if cap is not None:
            return cap
    return None


def _source_kind_from_decorator_types(
    decorator_types: Optional[List[str]],
) -> str:
    """Recover the ``source_kind`` string from a context's decorator tags."""
    if not decorator_types:
        return "annotation"
    for dec in decorator_types:
        if not dec or not dec.startswith("<"):
            continue
        leaf = dec.rsplit(".", 1)[-1]
        if leaf not in ("tool", "prompt", "resource"):
            continue
        # ``inner`` looks like ``annotation`` / ``registration`` /
        # ``registration.unresolved`` / ``registration.unresolved.template``.
        inner = dec[1:].rsplit(".", 1)[0]
        return inner.rstrip(">")
    return "annotation"


__all__ = [
    "CapabilityRecord",
    "CapabilityDetector",
    # Re-exported for backward compatibility with tests/integrations
    # that import these from ``native_analyzer`` directly.
    "_MCP_REGISTRATION_METHODS",
    "_MCP_LOW_LEVEL_REGISTRATION_METHODS",
    "_LOW_LEVEL_SCHEMA_TO_CAPABILITY",
    "_PY_MCP_CAPABILITY_TAGS",
    "_PY_MCP_LOWLEVEL_DECORATORS",
    "_TS_NON_FUNCTION_NODE_TYPES",
    "_MCP_ANNOTATION_RE",
    "_MCP_NAME_ARG_RE",
    "_MCP_ANNOTATION_IDENTIFIERS",
    "_TRUSTED_ANNOTATION_NAMESPACES",
    "_MCP_SDK_MODULE_PREFIXES",
    "_MCP_KNOWN_SERVER_CLASSES",
    "_MCP_PREFILTER_RE",
    "_PREFILTER_LANGUAGES",
    "_strip_string_quotes",
    "_normalize_capability",
    "_classify_template_subtype",
    "_python_decorator_capability",
    "_is_mcp_capability_decorator_set",
    "_is_same_ts_node",
    "_split_annotation_namespace",
    "_classify_mcp_annotation",
    "_parse_name_from_annotations",
]
