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

"""The tree-sitter backend of :class:`~.native_analyzer.NativeAnalyzer`.

Covers every non-Python language the analyzer understands: JS/TS, Go, Java,
Kotlin, C#, Ruby, Rust, PHP and Swift. See :mod:`.native_python_backend` for
why these are mixins rather than collaborators.
"""

import re as _re

from typing import Any, ClassVar, Dict, List, Optional, Set

from tree_sitter import Node

from .context_extractor import FunctionContext
from .dataflow.treesitter_analysis import TreeSitterDataflowAnalysis
from .taint.tracker import TaintStatus
from ...utils.ordering import dedupe

from .native_common import (
    TaintInfo,
    _LOW_LEVEL_SCHEMA_TO_CAPABILITY,
    _MCP_LOW_LEVEL_REGISTRATION_METHODS,
    _MCP_REGISTRATION_METHODS,
    _TS_MEMBER_EXPR_TYPES,
    _TS_NON_FUNCTION_NODE_TYPES,
    _classify_template_subtype,
    _is_same_ts_node,
    _normalize_capability,
    _normalize_module_specifier,
    _path_endswith_suffix,
    _strip_string_quotes,
)


class TreeSitterBackendMixin:
    """Tree-sitter capability extraction, mixed into ``NativeAnalyzer``."""

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
        # Positional slots preserve argument order so the first ref
        # (``tool.alias``) is not confused with later identifiers
        # (``toolDescription``, ``paramSchema``) in Graph-style loops.
        positional: List[tuple[str, Any]] = []

        for child in args_node.children:
            if child.type in ("(", ")", ",", "comment"):
                continue

            if child.type in func_types:
                positional.append(("inline", child))
                continue

            if child.type == "identifier":
                positional.append(("ref", self._ts_get_node_text(child)))
                continue

            if child.type in _TS_MEMBER_EXPR_TYPES:
                positional.append(("ref", self._ts_get_node_text(child)))
                continue

            if child.type in string_node_types:
                positional.append(
                    ("string", _strip_string_quotes(self._ts_get_node_text(child)))
                )
                continue

            if child.type in (
                "object",
                "object_expression",
                "literal_value",
                "composite_literal",
            ):
                obj_name, obj_handler = self._ts_extract_handler_from_object(
                    child, func_types
                )
                if obj_name:
                    positional.append(("string", obj_name))
                if obj_handler is not None:
                    positional.append(("inline", obj_handler))
                if not obj_name and obj_handler is None:
                    positional.append(("schema", None))
                continue

            if child.type == "unary_expression":
                for sub in child.children:
                    if sub.type in ("composite_literal", "literal_value"):
                        obj_name, obj_handler = self._ts_extract_handler_from_object(
                            sub, func_types
                        )
                        if obj_name:
                            positional.append(("string", obj_name))
                        if obj_handler is not None:
                            positional.append(("inline", obj_handler))
                        if not obj_name and obj_handler is None:
                            positional.append(("schema", None))
                        break

        for kind, val in positional:
            if kind == "string" and val:
                name = val
                break

        inline_handlers = [val for kind, val in positional if kind == "inline"]
        refs = [val for kind, val in positional if kind == "ref"]

        handler_node = inline_handlers[-1] if inline_handlers else None
        handler_name: Optional[str] = None

        if handler_node is None and refs:
            handler_name = refs[-1]

        if (
            name is None
            and refs
            and self.language in ("javascript", "typescript")
            and capability_method.lower() not in _MCP_LOW_LEVEL_REGISTRATION_METHODS
        ):
            name = refs[0]

        if handler_node is None and handler_name is None:
            return None

        return {
            "capability": override_capability or _normalize_capability(capability_method),
            "name": name,
            "handler_node": handler_node,
            "handler_name": handler_name,
        }
    _TS_ENDPOINT_NAME_FIELDS: tuple[str, ...] = (
        "name",
        "alias",
        "tool",
        "toolName",
    )
    _TS_ENDPOINT_ROUTE_FIELDS: ClassVar[Set[str]] = {"path", "method", "route", "url"}
    _TS_ENDPOINT_DESCRIPTOR_FIELDS: ClassVar[Set[str]] = {
        "fn",
        "handler",
        "execute",
        "callback",
        "description",
        "schema",
        "inputSchema",
        "parameters",
    }
    def _ts_collect_static_endpoint_tool_names(
        self,
        root: "Node",
        *,
        import_target_map: Optional[Dict[str, List[str]]] = None,
        cross_file_analyzer: Optional[Any] = None,
    ) -> List[str]:
        """Collect static MCP tool names from descriptor arrays.

        Only arrays reached through ``for (const tool of api.endpoints)``-style
        loops are considered (in-file and cross-file). A blanket walk of every
        array literal would mis-tag HTTP route tables and model catalogues as
        MCP tools.
        """
        names: List[str] = []
        seen: Set[str] = set()
        bindings = self._ts_build_simple_value_bindings(root)

        def add_name(value: Optional[str]) -> None:
            if value and value not in seen:
                seen.add(value)
                names.append(value)

        def visit(node: "Node") -> None:
            if node.type in ("for_in_statement", "for_of_statement"):
                src = self._ts_for_in_source_node(node)
                if src is not None:
                    array_node = self._ts_resolve_to_array_node(src, bindings, root)
                    if array_node is None:
                        array_node = self._ts_resolve_cross_file_endpoint_array(
                            src,
                            import_target_map=import_target_map,
                            cross_file_analyzer=cross_file_analyzer,
                        )
                    if array_node is not None:
                        for tool_name in self._ts_endpoint_names_in_array(array_node):
                            add_name(tool_name)
            for child in node.children:
                visit(child)

        visit(root)
        return names
    def _ts_endpoint_names_in_array(self, array_node: "Node") -> List[str]:
        """Return string tool names from object elements in an array literal."""
        out: List[str] = []
        for child in array_node.children:
            if child.type not in ("object", "object_expression"):
                continue
            tool_name: Optional[str] = None
            for name_field in self._TS_ENDPOINT_NAME_FIELDS:
                tool_name = self._ts_object_string_field(child, name_field)
                if tool_name:
                    break
            if not tool_name:
                continue
            if self._ts_object_has_any_field(child, self._TS_ENDPOINT_ROUTE_FIELDS):
                continue
            if not self._ts_object_has_any_field(
                child, self._TS_ENDPOINT_DESCRIPTOR_FIELDS
            ):
                continue
            out.append(tool_name)
        return out
    def _ts_build_simple_value_bindings(self, root: "Node") -> Dict[str, "Node"]:
        """Map ``const foo = ...`` initializer nodes for simple resolution."""
        bindings: Dict[str, "Node"] = {}

        def visit(node: "Node") -> None:
            if node.type == "export_statement":
                for child in node.children:
                    if child.type in (
                        "object",
                        "object_expression",
                        "array",
                        "array_expression",
                    ):
                        bindings.setdefault("default", child)
            if node.type == "variable_declarator":
                name_node = node.child_by_field_name("name")
                value_node = node.child_by_field_name("value")
                if (
                    name_node is not None
                    and value_node is not None
                    and name_node.type == "identifier"
                ):
                    bindings[self._ts_get_node_text(name_node)] = value_node
            for child in node.children:
                visit(child)

        visit(root)
        return bindings
    def _ts_for_in_source_node(self, for_node: "Node") -> Optional["Node"]:
        """Return the iterable expression in a ``for...of`` loop."""
        src = for_node.child_by_field_name("right")
        if src is not None:
            return src
        seen_of = False
        skip_types = {
            "for",
            "of",
            "const",
            "let",
            "var",
            "identifier",
            "(",
            ")",
            ";",
        }
        for child in for_node.children:
            if child.type == "of":
                seen_of = True
                continue
            if seen_of and child.type not in skip_types:
                return child
        return None
    def _ts_resolve_to_array_node(
        self,
        expr: "Node",
        bindings: Dict[str, "Node"],
        root: "Node",
    ) -> Optional["Node"]:
        """Resolve ``api.endpoints`` / ``tools`` to an array literal node."""
        if expr.type in ("array", "array_expression"):
            return expr
        if expr.type == "identifier":
            bound = bindings.get(self._ts_get_node_text(expr))
            if bound is not None and bound.type in ("array", "array_expression"):
                return bound
            return None
        if expr.type in _TS_MEMBER_EXPR_TYPES:
            obj_node = expr.child_by_field_name("object")
            prop_node = expr.child_by_field_name("property")
            if obj_node is None or prop_node is None:
                return None
            base_text = self._ts_get_node_text(obj_node)
            prop_text = self._ts_get_node_text(prop_node)
            if obj_node.type == "identifier":
                bound = bindings.get(base_text)
                if bound is not None and bound.type in (
                    "object",
                    "object_expression",
                ):
                    field_val = self._ts_object_field_value_node(bound, prop_text)
                    if field_val is not None and field_val.type in (
                        "array",
                        "array_expression",
                    ):
                        return field_val
        return None
    def _ts_object_field_value_node(
        self, obj_node: "Node", field: str
    ) -> Optional["Node"]:
        """Return the value node for ``field`` on an object literal."""
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
            if key == field:
                return value_node
        return None
    def _ts_resolve_cross_file_endpoint_array(
        self,
        expr: "Node",
        *,
        import_target_map: Optional[Dict[str, List[str]]] = None,
        cross_file_analyzer: Optional[Any] = None,
    ) -> Optional["Node"]:
        """Resolve ``api.endpoints`` / imported arrays to a remote array literal."""
        if not import_target_map or not cross_file_analyzer:
            return None
        files = getattr(cross_file_analyzer, "files", None)
        if not files:
            return None

        base_name: Optional[str] = None
        prop_name: Optional[str] = None
        if expr.type == "identifier":
            base_name = self._ts_get_node_text(expr)
        elif expr.type in _TS_MEMBER_EXPR_TYPES:
            obj_node = expr.child_by_field_name("object")
            prop_node = expr.child_by_field_name("property")
            if obj_node is not None and obj_node.type == "identifier" and prop_node is not None:
                base_name = self._ts_get_node_text(obj_node)
                prop_name = self._ts_get_node_text(prop_node)
        if not base_name:
            return None

        target_paths = import_target_map.get(base_name)
        if not target_paths:
            return None

        current_fp = str(self.file_path) if self.file_path else ""

        for fp, (tree, source_bytes) in files.items():
            fp_str = str(fp)
            if current_fp and fp_str == current_fp:
                continue
            if not any(_path_endswith_suffix(fp_str, tgt) for tgt in target_paths):
                continue

            try:
                remote_source = source_bytes.decode("utf-8")
            except UnicodeDecodeError:
                continue
            remote = self.__class__(remote_source, fp_str)
            remote_bindings = remote._ts_build_simple_value_bindings(tree.root_node)
            value_node = remote_bindings.get(base_name)
            if value_node is None:
                value_node = remote._ts_find_exported_binding(tree.root_node, base_name)
            if value_node is None and "default" in remote_bindings:
                value_node = remote_bindings.get("default")

            if value_node is None:
                continue

            if prop_name:
                if value_node.type not in ("object", "object_expression"):
                    continue
                field_val = remote._ts_object_field_value_node(value_node, prop_name)
                if field_val is not None and field_val.type in (
                    "array",
                    "array_expression",
                ):
                    return field_val
                continue

            if value_node.type in ("array", "array_expression"):
                return value_node

        return None
    def _ts_find_exported_binding(
        self, root: "Node", symbol: str
    ) -> Optional["Node"]:
        """Return the initializer for ``export const symbol = ...`` if present."""
        found: Optional["Node"] = None

        def visit(node: "Node") -> None:
            nonlocal found
            if found is not None:
                return
            if node.type == "export_statement":
                for child in node.children:
                    if child.type == "lexical_declaration":
                        for decl in child.children:
                            if decl.type != "variable_declarator":
                                continue
                            name_node = decl.child_by_field_name("name")
                            value_node = decl.child_by_field_name("value")
                            if (
                                name_node is not None
                                and value_node is not None
                                and name_node.type == "identifier"
                                and self._ts_get_node_text(name_node) == symbol
                            ):
                                found = value_node
                                return
            for child in node.children:
                visit(child)

        visit(root)
        return found
    def _ts_object_string_field(
        self, obj_node: "Node", field: str
    ) -> Optional[str]:
        """Return a string literal value for ``field`` on an object literal."""
        pair_types = {
            "pair",
            "field_initialization",
            "key_value",
            "object_property",
            "element",
        }
        string_node_types = {
            "string",
            "string_literal",
            "template_string",
            "raw_string_literal",
            "interpreted_string_literal",
        }
        for child in obj_node.children:
            if child.type not in pair_types:
                continue
            key_node = child.child_by_field_name("key")
            value_node = child.child_by_field_name("value")
            if key_node is None or value_node is None:
                continue
            key = _strip_string_quotes(self._ts_get_node_text(key_node).strip())
            if key != field:
                continue
            if value_node.type in string_node_types:
                return _strip_string_quotes(self._ts_get_node_text(value_node))
        return None
    def _ts_object_has_any_field(
        self, obj_node: "Node", fields: Set[str]
    ) -> bool:
        """Return True when ``obj_node`` defines any key in ``fields``."""
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
            if key_node is None:
                continue
            key = _strip_string_quotes(self._ts_get_node_text(key_node).strip())
            if key in fields:
                return True
        return False
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
        node_text = getattr(node, "text", None)
        if node_text is not None:
            return node_text.decode("utf-8")
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
        return dedupe(strings)[:50]
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
