# Copyright 2026 Cisco Systems, Inc. and its affiliates
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

"""JavaScript / TypeScript Function-Context Extractor.

Produces language-agnostic :class:`FunctionContext` records for MCP tool /
prompt / resource registrations in JS/TS source so the existing
:class:`AlignmentOrchestrator` can run docstring-vs-behaviour alignment
analysis without caring whether the source was Python or JavaScript.

Detection targets (high-level MCP SDK patterns):

* ``<expr>.tool("name", "description", schema, handler)``
* ``<expr>.tool("name", { description, inputSchema }, handler)``
* ``<expr>.registerTool("name", {...}, handler)``
* ``<expr>.prompt(...)`` / ``<expr>.registerPrompt(...)``
* ``<expr>.resource(...)`` / ``<expr>.registerResource(...)``

Low-level ``setRequestHandler(CallToolRequestSchema, ...)`` dispatchers are
NOT extracted per-tool — the orchestrator gets nothing useful from a single
giant handler routing N tools by name. Operators wanting coverage on those
should refactor to the high-level SDK.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    import tree_sitter_javascript
    import tree_sitter_typescript
    from tree_sitter import Language, Node, Parser
except ImportError as exc:  # pragma: no cover - import-time guard
    raise ImportError(
        "JS/TS behavioral analysis requires tree-sitter, "
        "tree-sitter-javascript, and tree-sitter-typescript. "
        "Reinstall mcpscanner or add the deps manually."
    ) from exc

from ..context_extractor import FunctionContext


logger = logging.getLogger(__name__)


# MCP SDK call names that register a tool/prompt/resource. Detection matches
# any ``<expr>.<name>(...)`` call where ``<name>`` is one of these. The
# leading expression is intentionally unconstrained — operators name their
# server object anything (``server``, ``mcp``, ``app``, ``s``, etc.).
_MCP_REGISTRATION_METHODS = frozenset(
    {
        "tool",
        "prompt",
        "resource",
        "registerTool",
        "registerPrompt",
        "registerResource",
    }
)

# Substrings used to confirm a file actually pulls in an MCP SDK. Each
# substring is matched (case-insensitive) against the text of every
# top-level import / require found in the file. When none match we still
# fall back to surface-shape heuristics, but only after logging so noisy
# false positives are at least traceable.
_MCP_IMPORT_HINTS = (
    "modelcontextprotocol",
    "@modelcontextprotocol",
    "mcp-server",
    "mcp_server",
    "mcp/server",
    "mcp_sdk",
    "mcp-sdk",
)

# Method names whose presence alone is too generic to attribute to MCP
# (``.tool``, ``.prompt``, ``.resource``). When we don't see any MCP-shaped
# import and the registration uses one of these short names, we treat the
# match as weakly attributed.
_AMBIGUOUS_METHOD_NAMES = frozenset({"tool", "prompt", "resource"})

# Heuristic pattern lists for the dataflow-light boolean indicators on
# FunctionContext. The Python extractor uses similar lists; mirror them here
# so the LLM prompt sees consistent signals across languages.
_FILE_PATTERNS = (
    "fs.",
    "readfile",
    "writefile",
    "createreadstream",
    "createwritestream",
    "openfile",
    "fs/promises",
    "require('fs')",
    'require("fs")',
    "from 'fs'",
    'from "fs"',
    "from 'node:fs'",
    'from "node:fs"',
)
_NETWORK_PATTERNS = (
    "fetch(",
    "axios",
    "got(",
    "http.request",
    "https.request",
    "http.get",
    "https.get",
    "net.connect",
    "websocket",
    "xmlhttprequest",
    "navigator.sendbeacon",
)
_SUBPROCESS_PATTERNS = (
    "child_process",
    "spawn(",
    "spawnsync",
    "exec(",
    "execsync",
    "execfile",
    "fork(",
    "shelljs",
)

# Dangerous JS sinks that mirror Python's eval/exec/compile/__import__.
_EVAL_EXEC_CALLS = frozenset(
    {"eval", "Function", "vm.runInThisContext", "vm.runInNewContext", "vm.runInContext"}
)

# Per-function caps to keep prompt size bounded; mirror Python extractor.
_MAX_STRING_LITERALS = 20
_MAX_LITERAL_LENGTH = 200
_MAX_ATTR_OPS = 20
_MAX_FUNCTION_CALLS_PER_HANDLER = 200
_MAX_ASSIGNMENTS_PER_HANDLER = 200


# Tree-sitter language singletons. Each language pack exposes a small C
# struct via PyCapsule, so cache them at module load.
_LANG_JS = Language(tree_sitter_javascript.language())
_LANG_TS = Language(tree_sitter_typescript.language_typescript())
_LANG_TSX = Language(tree_sitter_typescript.language_tsx())


def _language_for_path(path: Path) -> Optional[Language]:
    """Pick the tree-sitter language for a file by extension. Unknown
    extensions return ``None`` so the caller can skip the file without
    raising."""
    suffix = path.suffix.lower()
    if suffix in (".js", ".mjs", ".cjs", ".jsx"):
        return _LANG_JS
    if suffix == ".tsx":
        return _LANG_TSX
    if suffix in (".ts", ".mts", ".cts"):
        return _LANG_TS
    return None


class JSContextExtractor:
    """Extract :class:`FunctionContext` records from JS/TS source.

    Mirrors the public surface of
    :class:`mcpscanner.core.static_analysis.context_extractor.ContextExtractor`
    so downstream callers (and the orchestrator) don't need to special-case
    the language.
    """

    def __init__(self, source_code: str, file_path: str = "unknown.js"):
        """Parse ``source_code`` using the tree-sitter pack matching
        ``file_path``'s extension."""
        self.source_code = source_code
        self.file_path = Path(file_path)
        self._source_bytes = source_code.encode("utf-8", errors="replace")

        language = _language_for_path(self.file_path)
        if language is None:
            raise ValueError(
                f"Unsupported JS/TS extension for {file_path!r}; "
                f"expected one of .js/.mjs/.cjs/.jsx/.ts/.mts/.cts/.tsx"
            )

        parser = Parser(language)
        self._tree = parser.parse(self._source_bytes)
        self._root = self._tree.root_node

        # Cached top-level imports — computed once, reused per handler.
        self._module_imports: List[str] = self._extract_module_imports(self._root)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def extract_mcp_function_contexts(self) -> List[FunctionContext]:
        """Walk the CST and return one ``FunctionContext`` per MCP tool /
        prompt / resource registration found.

        Bare ``.tool``/``.prompt``/``.resource`` short names are common
        in non-MCP codebases too (graphics tools, prompt libraries, REST
        resource builders). When we hit one and the surrounding file
        doesn't import the MCP SDK we still emit the context but log at
        INFO with a ``weakly_attributed=true`` marker so operators can
        triage noise after the fact. ``registerTool``/``registerPrompt``/
        ``registerResource`` are MCP-specific enough that we don't flag
        them.
        """
        has_mcp_import = self._file_has_mcp_import()
        contexts: List[FunctionContext] = []
        for call_node, method_name in self._iter_mcp_registration_calls(self._root):
            weakly_attributed = (
                not has_mcp_import and method_name in _AMBIGUOUS_METHOD_NAMES
            )
            if weakly_attributed:
                logger.info(
                    "js_extractor weakly_attributed_match file=%s line=%d "
                    "method=%s -- no MCP-shaped import in file",
                    self.file_path,
                    call_node.start_point[0] + 1,
                    method_name,
                )
            try:
                ctx = self._build_context_from_registration(call_node, method_name)
            except Exception as e:  # noqa: BLE001 - extractor should never crash the scan
                logger.warning(
                    "js_extractor failed_registration file=%s line=%d method=%s error=%s",
                    self.file_path,
                    call_node.start_point[0] + 1,
                    method_name,
                    e,
                )
                continue
            if ctx is None:
                continue
            if weakly_attributed and ctx.decorator_params:
                # Surface the attribution hint to the orchestrator's
                # finding details. The prompt builder doesn't read this
                # but operators inspecting the raw JSON can.
                first_decorator = next(iter(ctx.decorator_params.values()))
                first_decorator["weakly_attributed"] = True
            contexts.append(ctx)
        return contexts

    def _file_has_mcp_import(self) -> bool:
        """Return True when at least one of the file's top-level imports
        contains a known MCP SDK substring. Cheap textual check; the
        prompt builder doesn't care which SDK we matched against."""
        joined = "\n".join(self._module_imports).lower()
        if not joined:
            return False
        return any(hint in joined for hint in _MCP_IMPORT_HINTS)

    # ------------------------------------------------------------------
    # Registration detection
    # ------------------------------------------------------------------

    def _iter_mcp_registration_calls(
        self, root: Node
    ) -> List[Tuple[Node, str]]:
        """Return ``[(call_node, method_name)]`` for every
        ``<expr>.<mcp-method>(...)`` invocation in the tree."""
        found: List[Tuple[Node, str]] = []
        stack: List[Node] = [root]
        while stack:
            node = stack.pop()
            if node.type == "call_expression":
                method = self._extract_member_method(node)
                if method is not None and method in _MCP_REGISTRATION_METHODS:
                    found.append((node, method))
            # Iterate in reverse so visitation order is roughly source order
            # (we pop from the end of the stack).
            for child in reversed(node.children):
                stack.append(child)
        return found

    def _extract_member_method(self, call_node: Node) -> Optional[str]:
        """Given a ``call_expression`` whose callee is a member access like
        ``server.tool``, return ``"tool"``. Anything else returns
        ``None``."""
        func = call_node.child_by_field_name("function")
        if func is None or func.type != "member_expression":
            return None
        prop = func.child_by_field_name("property")
        if prop is None:
            return None
        return self._text(prop)

    # ------------------------------------------------------------------
    # FunctionContext construction
    # ------------------------------------------------------------------

    def _build_context_from_registration(
        self, call_node: Node, method_name: str
    ) -> Optional[FunctionContext]:
        """Convert one ``<expr>.<method>(args)`` registration into a
        ``FunctionContext`` or ``None`` if we can't make sense of it."""
        args = self._registration_args(call_node)
        if not args:
            return None

        tool_name = self._extract_tool_name(args, method_name)
        if tool_name is None:
            # Without a name there is nothing useful to align against.
            return None

        decorator_params: Dict[str, Dict[str, Any]] = {
            method_name: {"name": tool_name}
        }
        # Many SDK variants accept a description either as a positional
        # string or as an options-object field. Pick whichever shows up.
        description = self._extract_tool_description(args)
        if description:
            decorator_params[method_name]["description"] = description

        handler = self._find_handler_among_args(args)
        if handler is None:
            # Registration without a function body — typically a constant
            # tool stub. Emit a stub context so the orchestrator can flag
            # description-only entries instead of silently dropping them.
            return self._stub_context(
                call_node, method_name, tool_name, decorator_params, description
            )

        return self._build_handler_context(
            call_node=call_node,
            method_name=method_name,
            tool_name=tool_name,
            decorator_params=decorator_params,
            description=description,
            handler=handler,
        )

    def _registration_args(self, call_node: Node) -> List[Node]:
        """Return the argument list of a ``call_expression`` without the
        wrapping parens / commas / comments."""
        args_node = call_node.child_by_field_name("arguments")
        if args_node is None:
            return []
        return [c for c in args_node.named_children if c.type != "comment"]

    def _extract_tool_name(
        self, args: List[Node], method_name: str
    ) -> Optional[str]:
        """The first positional argument is the tool name (string literal).
        Bail out for dynamic names — they're rare and don't carry a docstring
        we can align against."""
        if not args:
            return None
        first = args[0]
        if first.type == "string":
            return self._unquote_string(first) or None
        return None

    def _extract_tool_description(self, args: List[Node]) -> Optional[str]:
        """Pick description from positional string (arg 2) or
        ``{description: "..."}`` options object."""
        if len(args) >= 2 and args[1].type == "string":
            return self._unquote_string(args[1])
        for arg in args[1:]:
            if arg.type == "object":
                desc = self._object_field(arg, "description")
                if desc:
                    return desc
        return None

    def _find_handler_among_args(self, args: List[Node]) -> Optional[Node]:
        """Return the first function-like argument (arrow / function /
        async function). MCP SDKs always put the handler last, but be
        liberal."""
        for arg in args:
            if arg.type in (
                "arrow_function",
                "function_expression",
                "function",
            ):
                return arg
        return None

    def _stub_context(
        self,
        call_node: Node,
        method_name: str,
        tool_name: str,
        decorator_params: Dict[str, Dict[str, Any]],
        description: Optional[str],
    ) -> FunctionContext:
        """Build a near-empty context for a registration without a handler
        function. The LLM will only see name + description."""
        return FunctionContext(
            name=tool_name,
            decorator_types=[f"server.{method_name}"],
            decorator_params=decorator_params,
            docstring=description,
            parameters=[],
            return_type=None,
            line_number=call_node.start_point[0] + 1,
            imports=list(self._module_imports),
            function_calls=[],
            assignments=[],
            control_flow={
                "has_conditionals": False,
                "has_loops": False,
                "has_exception_handling": False,
                "has_pattern_matching": False,
            },
            parameter_flows=[],
            constants={},
            variable_dependencies={},
            has_file_operations=False,
            has_network_operations=False,
            has_subprocess_calls=False,
            has_eval_exec=False,
            has_dangerous_imports=bool(self._module_imports),
        )

    def _build_handler_context(
        self,
        *,
        call_node: Node,
        method_name: str,
        tool_name: str,
        decorator_params: Dict[str, Dict[str, Any]],
        description: Optional[str],
        handler: Node,
    ) -> FunctionContext:
        """Walk inside the handler body to populate the dataflow-light
        FunctionContext fields the orchestrator's prompt builder reads."""
        parameters = self._extract_handler_parameters(handler)
        body = handler.child_by_field_name("body")

        function_calls = self._collect_function_calls(body)
        assignments = self._collect_assignments(body)
        string_literals = self._collect_string_literals(body)
        return_expressions = self._collect_return_expressions(body)
        control_flow = self._control_flow_summary(body)
        exception_handlers = self._collect_exception_handlers(body)
        env_var_access = self._collect_env_var_access(body)
        attribute_access = self._collect_attribute_access(body)
        constants = self._collect_constant_assignments(body)
        variable_dependencies = self._collect_variable_dependencies(body)

        body_text_lower = (self._text(body) if body is not None else "").lower()
        has_file_ops = any(p in body_text_lower for p in _FILE_PATTERNS)
        has_network_ops = any(p in body_text_lower for p in _NETWORK_PATTERNS)
        has_subprocess = any(p in body_text_lower for p in _SUBPROCESS_PATTERNS)
        has_eval_exec = self._has_eval_exec(body)

        docstring = description or self._jsdoc_above(call_node)

        return FunctionContext(
            name=tool_name,
            decorator_types=[f"server.{method_name}"],
            decorator_params=decorator_params,
            docstring=docstring,
            parameters=parameters,
            return_type=self._extract_return_type(handler),
            line_number=call_node.start_point[0] + 1,
            imports=list(self._module_imports),
            function_calls=function_calls[:_MAX_FUNCTION_CALLS_PER_HANDLER],
            assignments=assignments[:_MAX_ASSIGNMENTS_PER_HANDLER],
            control_flow=control_flow,
            # Forward-flow dataflow analysis isn't implemented for JS in
            # this pass — leave empty so the prompt builder skips the
            # section instead of fabricating evidence.
            parameter_flows=[],
            constants=constants,
            variable_dependencies=variable_dependencies,
            has_file_operations=has_file_ops,
            has_network_operations=has_network_ops,
            has_subprocess_calls=has_subprocess,
            has_eval_exec=has_eval_exec,
            has_dangerous_imports=bool(self._module_imports),
            string_literals=string_literals,
            return_expressions=return_expressions,
            exception_handlers=exception_handlers,
            env_var_access=env_var_access,
            attribute_access=attribute_access,
        )

    # ------------------------------------------------------------------
    # Handler walking helpers
    # ------------------------------------------------------------------

    def _extract_handler_parameters(self, handler: Node) -> List[Dict[str, Any]]:
        """Return a list of ``{"name": ..., "type": ...}`` for the handler's
        formal parameters. Destructured params (``{a, b}``) are flattened
        into the field names so the orchestrator sees per-field
        signals."""
        out: List[Dict[str, Any]] = []
        params_node = handler.child_by_field_name("parameters")
        if params_node is None:
            return out
        for param in params_node.named_children:
            if param.type == "comment":
                continue
            entries = self._param_node_to_entries(param)
            out.extend(entries)
        return out

    def _param_node_to_entries(self, param: Node) -> List[Dict[str, Any]]:
        """Flatten a parameter node into ``[{"name", "type"?}]``. Handles
        identifier, object_pattern, array_pattern, and required_parameter
        (TS)."""
        # TS adds a wrapping ``required_parameter``/``optional_parameter`` node.
        if param.type in ("required_parameter", "optional_parameter"):
            inner = param.child_by_field_name("pattern")
            type_ann = param.child_by_field_name("type")
            type_str = self._type_annotation_text(type_ann) if type_ann else None
            if inner is None:
                return []
            return [
                {**entry, **({"type": type_str} if type_str and "type" not in entry else {})}
                for entry in self._param_node_to_entries(inner)
            ]

        if param.type == "identifier":
            return [{"name": self._text(param)}]
        if param.type == "rest_pattern":
            inner = param.named_children[0] if param.named_children else None
            if inner is None:
                return [{"name": "...rest"}]
            inner_entries = self._param_node_to_entries(inner)
            return [{**e, "name": f"...{e['name']}"} for e in inner_entries]
        if param.type == "assignment_pattern":
            left = param.child_by_field_name("left")
            if left is not None:
                return self._param_node_to_entries(left)
            return []
        if param.type == "object_pattern":
            entries: List[Dict[str, Any]] = []
            for prop in param.named_children:
                if prop.type == "shorthand_property_identifier_pattern":
                    entries.append({"name": self._text(prop)})
                elif prop.type == "pair_pattern":
                    key = prop.child_by_field_name("key")
                    if key is not None:
                        entries.append({"name": self._text(key)})
                elif prop.type == "object_assignment_pattern":
                    left = prop.child_by_field_name("left")
                    if left is not None:
                        entries.extend(self._param_node_to_entries(left))
            return entries
        if param.type == "array_pattern":
            entries = []
            for i, item in enumerate(param.named_children):
                if item.type == "identifier":
                    entries.append({"name": self._text(item)})
                else:
                    entries.append({"name": f"_arr{i}"})
            return entries
        return []

    def _extract_return_type(self, handler: Node) -> Optional[str]:
        """Extract a TS return-type annotation from the handler if present."""
        ret = handler.child_by_field_name("return_type")
        if ret is None:
            return None
        return self._type_annotation_text(ret)

    def _type_annotation_text(self, node: Node) -> Optional[str]:
        """Return the text of a TS type annotation, stripping the leading
        ``:`` if present."""
        if node is None:
            return None
        text = self._text(node).strip()
        if text.startswith(":"):
            text = text[1:].strip()
        return text or None

    def _control_flow_summary(self, body: Optional[Node]) -> Dict[str, Any]:
        """Mirror Python's ``control_flow`` summary keys."""
        if body is None:
            return {
                "has_conditionals": False,
                "has_loops": False,
                "has_exception_handling": False,
                "has_pattern_matching": False,
            }
        types = self._collect_node_types(body)
        return {
            "has_conditionals": bool(
                {"if_statement", "ternary_expression", "switch_statement"} & types
            ),
            "has_loops": bool(
                {"for_statement", "for_in_statement", "for_of_statement", "while_statement", "do_statement"}
                & types
            ),
            "has_exception_handling": "try_statement" in types,
            "has_pattern_matching": "switch_statement" in types,
        }

    def _collect_node_types(self, root: Node) -> Set[str]:
        """Return the set of CST node types reachable from ``root``."""
        seen: Set[str] = set()
        stack = [root]
        while stack:
            node = stack.pop()
            seen.add(node.type)
            stack.extend(node.children)
        return seen

    def _collect_function_calls(self, body: Optional[Node]) -> List[Dict[str, Any]]:
        """Walk the body for ``call_expression`` nodes and return ``{name,
        args, line}`` records."""
        if body is None:
            return []
        out: List[Dict[str, Any]] = []
        stack = [body]
        while stack:
            node = stack.pop()
            if node.type == "call_expression":
                callee = node.child_by_field_name("function")
                args_node = node.child_by_field_name("arguments")
                arg_strs: List[str] = []
                if args_node is not None:
                    for arg in args_node.named_children:
                        if arg.type == "comment":
                            continue
                        arg_strs.append(self._text(arg)[:200])
                out.append(
                    {
                        "name": self._text(callee) if callee is not None else "",
                        "args": arg_strs,
                        "line": node.start_point[0] + 1,
                    }
                )
            stack.extend(node.children)
        return out

    def _collect_assignments(self, body: Optional[Node]) -> List[Dict[str, Any]]:
        """Collect variable declarations and assignment expressions."""
        if body is None:
            return []
        out: List[Dict[str, Any]] = []
        stack = [body]
        while stack:
            node = stack.pop()
            if node.type == "variable_declarator":
                name_node = node.child_by_field_name("name")
                value_node = node.child_by_field_name("value")
                if name_node is not None and name_node.type == "identifier":
                    out.append(
                        {
                            "variable": self._text(name_node),
                            "value": self._text(value_node)[:200] if value_node else "<no value>",
                            "line": node.start_point[0] + 1,
                            "type": "declarator",
                        }
                    )
            elif node.type == "assignment_expression":
                left = node.child_by_field_name("left")
                right = node.child_by_field_name("right")
                if left is not None:
                    out.append(
                        {
                            "variable": self._text(left),
                            "value": self._text(right)[:200] if right else "<no value>",
                            "line": node.start_point[0] + 1,
                            "type": "assign",
                        }
                    )
            elif node.type == "augmented_assignment_expression":
                left = node.child_by_field_name("left")
                right = node.child_by_field_name("right")
                if left is not None:
                    out.append(
                        {
                            "variable": self._text(left),
                            "value": self._text(right)[:200] if right else "<no value>",
                            "line": node.start_point[0] + 1,
                            "type": "augmented_assign",
                        }
                    )
            stack.extend(node.children)
        return out

    def _collect_string_literals(self, body: Optional[Node]) -> List[str]:
        """Collect deduplicated string literals (incl. template strings
        without substitutions). Long strings are truncated."""
        if body is None:
            return []
        seen: Set[str] = set()
        out: List[str] = []
        stack = [body]
        while stack:
            node = stack.pop()
            if node.type == "string":
                text = self._unquote_string(node)
                if text and text not in seen:
                    seen.add(text)
                    out.append(text[:_MAX_LITERAL_LENGTH])
                    if len(out) >= _MAX_STRING_LITERALS:
                        return out
            elif node.type == "template_string":
                # Skip template strings with interpolation — they're not
                # useful as opaque literals.
                if not any(
                    c.type == "template_substitution" for c in node.named_children
                ):
                    text = self._text(node).strip("`")
                    if text and text not in seen:
                        seen.add(text)
                        out.append(text[:_MAX_LITERAL_LENGTH])
                        if len(out) >= _MAX_STRING_LITERALS:
                            return out
            stack.extend(node.children)
        return out

    def _collect_return_expressions(self, body: Optional[Node]) -> List[str]:
        """Return the text of each ``return <expr>;`` statement in the
        body, truncated."""
        if body is None:
            return []
        out: List[str] = []
        stack = [body]
        while stack:
            node = stack.pop()
            if node.type == "return_statement":
                if node.named_children:
                    out.append(self._text(node.named_children[0])[:200])
                else:
                    out.append("<empty return>")
            stack.extend(node.children)
        return out

    def _collect_exception_handlers(
        self, body: Optional[Node]
    ) -> List[Dict[str, Any]]:
        """Collect ``catch`` clauses with their declared exception type
        (if any) and a 'silent' flag for empty handlers."""
        if body is None:
            return []
        out: List[Dict[str, Any]] = []
        stack = [body]
        while stack:
            node = stack.pop()
            if node.type == "catch_clause":
                param = node.child_by_field_name("parameter")
                block = node.child_by_field_name("body")
                is_silent = block is not None and not [
                    c for c in block.named_children if c.type != "comment"
                ]
                out.append(
                    {
                        "line": node.start_point[0] + 1,
                        "exception_type": self._text(param) if param else "any",
                        "has_body": block is not None,
                        "is_silent": is_silent,
                    }
                )
            stack.extend(node.children)
        return out

    def _collect_env_var_access(self, body: Optional[Node]) -> List[str]:
        """Find ``process.env.X`` and ``process.env["X"]`` accesses."""
        if body is None:
            return []
        out: List[str] = []
        seen: Set[str] = set()
        stack = [body]
        while stack:
            node = stack.pop()
            if node.type == "member_expression":
                text = self._text(node)
                if text.startswith("process.env.") or text.startswith("process.env["):
                    if text not in seen:
                        seen.add(text)
                        out.append(text[:120])
            elif node.type == "subscript_expression":
                obj = node.child_by_field_name("object")
                if obj is not None and self._text(obj) == "process.env":
                    text = self._text(node)
                    if text not in seen:
                        seen.add(text)
                        out.append(text[:120])
            stack.extend(node.children)
        return out

    def _collect_attribute_access(
        self, body: Optional[Node]
    ) -> List[Dict[str, Any]]:
        """Collect deduplicated member accesses (``obj.attr``) with
        type=read/write inferred from whether they appear on the LHS of an
        assignment."""
        if body is None:
            return []
        out: List[Dict[str, Any]] = []
        seen: Set[Tuple[str, str, str]] = set()
        stack = [body]
        while stack:
            node = stack.pop()
            if node.type == "assignment_expression":
                left = node.child_by_field_name("left")
                if left is not None and left.type == "member_expression":
                    self._maybe_record_attr(left, "write", seen, out, node)
            elif node.type == "member_expression":
                self._maybe_record_attr(node, "read", seen, out, node)
            stack.extend(node.children)
            if len(out) >= _MAX_ATTR_OPS:
                break
        return out

    def _maybe_record_attr(
        self,
        member: Node,
        kind: str,
        seen: Set[Tuple[str, str, str]],
        out: List[Dict[str, Any]],
        owner_node: Node,
    ) -> None:
        obj = member.child_by_field_name("object")
        prop = member.child_by_field_name("property")
        if obj is None or prop is None:
            return
        obj_text = self._text(obj)
        prop_text = self._text(prop)
        key = (kind, obj_text, prop_text)
        if key in seen:
            return
        seen.add(key)
        out.append(
            {
                "type": kind,
                "object": obj_text,
                "attribute": prop_text,
                "line": owner_node.start_point[0] + 1,
            }
        )

    def _collect_constant_assignments(self, body: Optional[Node]) -> Dict[str, Any]:
        """Pick up ``const NAME = <literal>;`` style constants. Only
        primitive literals (string/number/boolean) are recorded — anything
        else is too noisy."""
        if body is None:
            return {}
        out: Dict[str, Any] = {}
        stack = [body]
        while stack:
            node = stack.pop()
            if node.type == "lexical_declaration":
                kind_node = node.child(0)
                # ``const`` only — ``let`` re-assigns, not a constant.
                if kind_node is not None and self._text(kind_node) == "const":
                    for decl in node.named_children:
                        if decl.type != "variable_declarator":
                            continue
                        name_node = decl.child_by_field_name("name")
                        value_node = decl.child_by_field_name("value")
                        if name_node is None or name_node.type != "identifier":
                            continue
                        if value_node is None:
                            continue
                        value = self._literal_value(value_node)
                        if value is not None:
                            out[self._text(name_node)] = value
            stack.extend(node.children)
        return out

    def _literal_value(self, node: Node) -> Optional[Any]:
        if node.type == "string":
            return self._unquote_string(node)
        if node.type == "number":
            try:
                text = self._text(node)
                if "." in text or "e" in text.lower():
                    return float(text)
                return int(text, 0)
            except ValueError:
                return None
        if node.type in ("true", "false"):
            return node.type == "true"
        if node.type == "null":
            return None
        return None

    def _collect_variable_dependencies(
        self, body: Optional[Node]
    ) -> Dict[str, List[str]]:
        """Map each declared variable to the list of identifier names that
        appear on its RHS. Mirrors Python ``ContextExtractor``."""
        if body is None:
            return {}
        deps: Dict[str, List[str]] = {}
        stack = [body]
        while stack:
            node = stack.pop()
            if node.type == "variable_declarator":
                name_node = node.child_by_field_name("name")
                value_node = node.child_by_field_name("value")
                if (
                    name_node is not None
                    and name_node.type == "identifier"
                    and value_node is not None
                ):
                    deps[self._text(name_node)] = self._collect_identifiers(value_node)
            stack.extend(node.children)
        return deps

    def _collect_identifiers(self, node: Node) -> List[str]:
        out: List[str] = []
        seen: Set[str] = set()
        stack = [node]
        while stack:
            cur = stack.pop()
            if cur.type == "identifier":
                ident = self._text(cur)
                if ident not in seen:
                    seen.add(ident)
                    out.append(ident)
            stack.extend(cur.children)
        return out

    def _has_eval_exec(self, body: Optional[Node]) -> bool:
        if body is None:
            return False
        stack = [body]
        while stack:
            node = stack.pop()
            if node.type == "call_expression":
                callee = node.child_by_field_name("function")
                if callee is not None and self._text(callee) in _EVAL_EXEC_CALLS:
                    return True
            elif node.type == "new_expression":
                ctor = node.child_by_field_name("constructor")
                if ctor is not None and self._text(ctor) == "Function":
                    return True
            stack.extend(node.children)
        return False

    # ------------------------------------------------------------------
    # JSDoc / comments
    # ------------------------------------------------------------------

    def _jsdoc_above(self, call_node: Node) -> Optional[str]:
        """Return the text of a JSDoc-style block comment (``/** ... */``)
        immediately preceding the registration call's enclosing statement,
        if any. The comment is normalised to its description content."""
        stmt = self._enclosing_statement(call_node)
        if stmt is None:
            return None
        prev = stmt.prev_named_sibling
        # tree-sitter exposes comments as siblings at the program level.
        # The ``prev_named_sibling`` walks past whitespace; if the previous
        # named node is a comment whose text starts with ``/**`` we use it.
        if prev is None or prev.type != "comment":
            return None
        text = self._text(prev).strip()
        if not text.startswith("/**"):
            return None
        return self._normalise_jsdoc(text)

    def _enclosing_statement(self, node: Node) -> Optional[Node]:
        cur: Optional[Node] = node
        while cur is not None and "_statement" not in cur.type:
            cur = cur.parent
        return cur

    @staticmethod
    def _normalise_jsdoc(comment: str) -> str:
        """Strip ``/** ... */`` and leading ``*`` markers, return the
        descriptive prose."""
        inner = comment.strip()
        if inner.startswith("/**"):
            inner = inner[3:]
        if inner.endswith("*/"):
            inner = inner[:-2]
        out_lines: List[str] = []
        for line in inner.splitlines():
            stripped = line.strip()
            if stripped.startswith("*"):
                stripped = stripped[1:].strip()
            if stripped:
                out_lines.append(stripped)
        return " ".join(out_lines).strip()

    # ------------------------------------------------------------------
    # Top-level imports
    # ------------------------------------------------------------------

    def _extract_module_imports(self, root: Node) -> List[str]:
        """Return top-level ESM ``import`` statements and CommonJS
        ``require(...)`` calls in source order. The list is what
        FunctionContext.imports stores — text of each statement, truncated
        and deduplicated."""
        out: List[str] = []
        seen: Set[str] = set()

        for child in root.named_children:
            if child.type == "import_statement":
                text = self._text(child).rstrip(";").strip()
                if text and text not in seen:
                    seen.add(text)
                    out.append(text[:300])
            elif child.type in ("lexical_declaration", "variable_declaration"):
                # const/let/var X = require('foo')
                if any(
                    self._is_require_call(c) for c in self._walk_descendants(child)
                ):
                    text = self._text(child).rstrip(";").strip()
                    if text and text not in seen:
                        seen.add(text)
                        out.append(text[:300])
            elif child.type == "expression_statement":
                # bare require('foo') — uncommon but possible
                inner = child.named_children[0] if child.named_children else None
                if inner is not None and self._is_require_call(inner):
                    text = self._text(child).rstrip(";").strip()
                    if text and text not in seen:
                        seen.add(text)
                        out.append(text[:300])
        return out

    def _is_require_call(self, node: Node) -> bool:
        if node.type != "call_expression":
            return False
        callee = node.child_by_field_name("function")
        return callee is not None and self._text(callee) == "require"

    def _walk_descendants(self, root: Node):
        stack = [root]
        while stack:
            node = stack.pop()
            yield node
            stack.extend(node.children)

    # ------------------------------------------------------------------
    # Generic helpers
    # ------------------------------------------------------------------

    def _object_field(self, obj_node: Node, field: str) -> Optional[str]:
        """Look up a string-valued property in an ``object`` literal."""
        for prop in obj_node.named_children:
            if prop.type != "pair":
                continue
            key = prop.child_by_field_name("key")
            value = prop.child_by_field_name("value")
            if key is None or value is None:
                continue
            key_text = self._text(key).strip("'\"")
            if key_text == field and value.type == "string":
                return self._unquote_string(value)
        return None

    def _text(self, node: Optional[Node]) -> str:
        """Return the source slice corresponding to ``node`` as a string.
        Decoding errors fall back to replacement characters so the
        extractor never raises on malformed UTF-8."""
        if node is None:
            return ""
        return self._source_bytes[node.start_byte : node.end_byte].decode(
            "utf-8", errors="replace"
        )

    def _unquote_string(self, node: Node) -> str:
        """Strip the outer quote characters from a tree-sitter ``string``
        node. The ``string_fragment`` child holds the real content with
        escapes still in place; that's fine for our purposes."""
        fragments = [c for c in node.named_children if c.type == "string_fragment"]
        if fragments:
            return self._text(fragments[0])
        text = self._text(node)
        if len(text) >= 2 and text[0] == text[-1] and text[0] in ("'", '"', "`"):
            return text[1:-1]
        return text
