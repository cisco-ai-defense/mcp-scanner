# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Fuse caller CFG facts with callee formal parameters at call sites."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Any

from tree_sitter import Node, Parser

from ..parser.treesitter_parser import _get_language
from .models import CodeEdge, CodeGraph, Provenance

_TS_LANGS = frozenset(
    {
        "javascript",
        "typescript",
        "tsx",
        "go",
        "rust",
        "java",
        "kotlin",
        "c_sharp",
        "ruby",
        "php",
    }
)
_TS_CALL_TYPES = frozenset(
    {
        "call_expression",
        "new_expression",
        "method_invocation",
        "object_creation_expression",
        "invocation_expression",
        "function_call_expression",
        "member_call_expression",
        "scoped_call_expression",
        "call",
        "method_call",
        "macro_invocation",
    }
)
_TS_FUNC_TYPES = frozenset(
    {
        "function_declaration",
        "function_expression",
        "arrow_function",
        "method_definition",
        "method_declaration",
        "function_item",
        "method",
        "singleton_method",
        "function_definition",
        "local_function_statement",
        "secondary_constructor",
        "constructor_declaration",
    }
)


@dataclass
class ParamBinding:
    """Maps a tainted value at the call site to a callee formal parameter."""

    caller_taint: str
    callee_param: str
    provenance: Provenance
    confidence: float = 1.0
    line: int | None = None


def extract_function_parameters(func_node: Any, language: str) -> list[dict[str, Any]]:
    """
    Extract formal parameters from a function AST node.
    
    Parameters:
    	func_node (Any): Function AST node whose parameters should be extracted.
    	language (str): Source language of the function node.
    
    Returns:
    	list[dict[str, Any]]: Parameter records containing each parameter's name and positional index.
    """
    if language == "python":
        return _python_parameters(func_node)
    return _treesitter_parameters(func_node)


def _python_parameters(node: ast.AST) -> list[dict[str, Any]]:
    """Extract positional parameters from a Python function, excluding ``self``.
    
    Parameters:
    	node (ast.AST): The function node to inspect.
    
    Returns:
    	list[dict[str, Any]]: Parameter records containing each parameter's name and positional index.
    """
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return []
    params: list[dict[str, Any]] = []
    for index, arg in enumerate(node.args.args):
        if arg.arg == "self":
            continue
        params.append({"name": arg.arg, "index": index})
    return params


def _treesitter_parameters(node: Node) -> list[dict[str, Any]]:
    """
    Extract formal parameter names and positional indexes from a Tree-sitter function node.
    
    Parameters:
    	node (Node): The Tree-sitter function node whose parameters should be extracted.
    
    Returns:
    	list[dict[str, Any]]: Parameter records containing each parameter's ``name`` and zero-based ``index``.
    """
    if node is None:
        return []
    params_node = node.child_by_field_name("parameters") or node.child_by_field_name(
        "formal_parameters"
    )
    if params_node is None:
        return []
    params: list[dict[str, Any]] = []
    index = 0
    for child in params_node.children:
        if child.type in {",", "(", ")", "[", "]"}:
            continue
        if child.type == "self_parameter":
            continue
        if child.type in (
            "identifier",
            "required_parameter",
            "optional_parameter",
            "formal_parameter",
            "parameter_declaration",
            "simple_parameter",
            "parameter",
        ):
            name = _treesitter_param_name(child)
            if name and name not in {"self", "this"}:
                params.append({"name": name, "index": index})
                index += 1
    return params


def _treesitter_param_name(node: Node) -> str:
    """
    Extracts a parameter name from a Tree-sitter node.
    
    Parameters:
    	node (Node): Tree-sitter node representing a formal parameter.
    
    Returns:
    	str: The parameter name, or an empty string when no identifier is found.
    """
    name_node = node.child_by_field_name("name")
    if name_node is not None and name_node.type == "identifier":
        return name_node.text.decode("utf-8") if hasattr(name_node, "text") else ""
    if node.type == "identifier":
        return node.text.decode("utf-8") if hasattr(node, "text") else ""
    for child in node.children:
        if child.type == "identifier":
            return child.text.decode("utf-8") if hasattr(child, "text") else ""
    return ""


def _python_call_name(node: ast.Call) -> str:
    """
    Build the dotted name of a Python call target.
    
    Parameters:
        node (ast.Call): Call expression whose target name is extracted.
    
    Returns:
        str: The direct or attribute-based call name, or an empty string when the target has no supported name.
    """
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        parts: list[str] = []
        current: ast.expr = func
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        parts.reverse()
        return ".".join(parts)
    return ""


def _expr_uses_name(expr: ast.AST, name: str) -> bool:
    """Determine whether an AST expression references a specified name.
    
    Parameters:
    	expr (ast.AST): The expression to inspect.
    	name (str): The identifier to search for.
    
    Returns:
    	bool: `true` if the expression references the name, `false` otherwise.
    """
    for node in ast.walk(expr):
        if isinstance(node, ast.Name) and node.id == name:
            return True
    return False


class CFGFusionEngine:
    """Connect call-graph edges to callee CFGs via argument→parameter bindings."""

    def __init__(
        self,
        graph: CodeGraph,
        *,
        classic: Any | None = None,
    ) -> None:
        """Initialize the fusion engine with a code graph and optional classic dataflow engine.
        
        Parameters:
        	graph (CodeGraph): Code graph used to resolve call edges and source information.
        	classic (Any | None): Optional dataflow engine used to expand active taints.
        """
        self._graph = graph
        if classic is None:
            from .classic_dataflow import ClassicDataflowEngine

            classic = ClassicDataflowEngine(graph)
        self._classic = classic

    def bindings_for_edge(
        self,
        edge: CodeEdge,
        active_taints: set[str],
    ) -> list[ParamBinding]:
        """
        Infer which callee parameters receive tainted values across a call edge.
        
        Parameters:
            edge (CodeEdge): Call-graph edge connecting the caller and callee.
            active_taints (set[str]): Tainted caller values to propagate.
        
        Returns:
            list[ParamBinding]: Bindings between active caller taints and callee parameters.
        """
        if not active_taints or edge.relation.value != "calls":
            return []

        caller_id = edge.source
        callee_id = edge.target
        if callee_id not in self._graph.nodes:
            return []

        callee_node = self._graph.nodes[callee_id]
        callee_params = callee_node.metadata.get("parameters") or []
        if not callee_params:
            return []

        language = self._normalize_language(self._graph.language or callee_node.language)
        if language == "python":
            return self._python_bindings(caller_id, callee_id, edge, active_taints, callee_params)
        if language in _TS_LANGS:
            return self._treesitter_bindings(
                caller_id, callee_id, edge, active_taints, callee_params, language
            )
        return self._heuristic_bindings(active_taints, callee_params)

    @staticmethod
    def _normalize_language(language: str) -> str:
        """Normalize a language name for internal dispatch."""
        lang = (language or "python").lower()
        if lang == "c#":
            return "c_sharp"
        return lang

    def _heuristic_bindings(
        self,
        active_taints: set[str],
        callee_params: list[dict[str, Any]],
    ) -> list[ParamBinding]:
        """
        Infer taint bindings by matching taint names to callee parameters or using the first parameter as a positional fallback.
        
        Parameters:
        	active_taints (set[str]): Taint names to bind.
        	callee_params (list[dict[str, Any]]): Callee parameter metadata.
        
        Returns:
        	list[ParamBinding]: Inferred taint-to-parameter bindings.
        """
        bindings: list[ParamBinding] = []
        param_names = [p["name"] for p in callee_params]
        for taint in active_taints:
            if taint in param_names:
                bindings.append(
                    ParamBinding(
                        caller_taint=taint,
                        callee_param=taint,
                        provenance=Provenance.INFERRED,
                        confidence=0.85,
                    )
                )
                continue
            if callee_params:
                bindings.append(
                    ParamBinding(
                        caller_taint=taint,
                        callee_param=callee_params[0]["name"],
                        provenance=Provenance.INFERRED,
                        confidence=0.65,
                    )
                )
        return bindings

    def _python_bindings(
        self,
        caller_id: str,
        callee_id: str,
        edge: CodeEdge,
        active_taints: set[str],
        callee_params: list[dict[str, Any]],
    ) -> list[ParamBinding]:
        """Map tainted Python call arguments to the corresponding callee parameters.
        
        Parameters:
            caller_id (str): Identifier of the caller function.
            callee_id (str): Identifier of the callee function.
            edge (CodeEdge): Call-graph edge containing the call expression.
            active_taints (set[str]): Taints active in the caller.
            callee_params (list[dict[str, Any]]): Callee parameter metadata indexed by position.
        
        Returns:
            list[ParamBinding]: Extracted taint bindings, or heuristic bindings when precise analysis is unavailable.
        """
        caller_file, _, caller_label = _split_node_id(caller_id)
        _, _, callee_label = _split_node_id(callee_id)
        source = self._graph.source_registry.get(caller_file)
        if not source:
            return self._heuristic_bindings(active_taints, callee_params)

        try:
            tree = ast.parse(source)
        except SyntaxError:
            return self._heuristic_bindings(active_taints, callee_params)

        caller_func = _find_python_function(tree, caller_label)
        if caller_func is None:
            return self._heuristic_bindings(active_taints, callee_params)

        expanded_taints = self._classic.expand_active_taints(
            caller_id, caller_func, active_taints
        )

        call_label = edge.call_expression or callee_label.split(".")[-1]
        call_sites = _find_python_calls(caller_func, call_label, callee_label)

        bindings: list[ParamBinding] = []
        param_by_index = {p["index"]: p["name"] for p in callee_params}
        for call in call_sites:
            for arg_index, arg in enumerate(call.args):
                callee_param = param_by_index.get(arg_index)
                if not callee_param:
                    continue
                for taint in expanded_taints:
                    if not _arg_carries_taint(arg, taint):
                        continue
                    if isinstance(arg, ast.Name):
                        line = getattr(call, "lineno", None)
                        if isinstance(line, int) and not self._classic.is_live_at_line(
                            caller_id, arg.id, line
                        ):
                            continue
                    bindings.append(
                        ParamBinding(
                            caller_taint=taint,
                            callee_param=callee_param,
                            provenance=Provenance.EXTRACTED,
                            confidence=1.0,
                            line=getattr(call, "lineno", None),
                        )
                    )
        if bindings:
            return _dedupe_bindings(bindings)
        return self._heuristic_bindings(active_taints, callee_params)

    def _treesitter_bindings(
        self,
        caller_id: str,
        callee_id: str,
        edge: CodeEdge,
        active_taints: set[str],
        callee_params: list[dict[str, Any]],
        language: str,
    ) -> list[ParamBinding]:
        """
        Map tainted caller arguments to the corresponding callee parameters for a Tree-sitter-supported language.
        
        Parameters:
            caller_id (str): Identifier of the caller function.
            callee_id (str): Identifier of the callee function.
            edge (CodeEdge): Call-graph edge connecting the caller and callee.
            active_taints (set[str]): Taint names active in the caller.
            callee_params (list[dict[str, Any]]): Callee parameter metadata indexed by argument position.
            language (str): Source language used to parse the caller.
        
        Returns:
            list[ParamBinding]: Extracted argument-to-parameter bindings, or heuristic bindings when precise analysis is unavailable.
        """
        caller_file, _, caller_label = _split_node_id(caller_id)
        _, _, callee_label = _split_node_id(callee_id)
        source = self._graph.source_registry.get(caller_file)
        if not source:
            return self._heuristic_bindings(active_taints, callee_params)

        ts_lang = "typescript" if language == "tsx" else language
        ts_language = _get_language(ts_lang)
        if ts_language is None:
            return self._heuristic_bindings(active_taints, callee_params)

        source_bytes = source.encode("utf-8")
        root = Parser(ts_language).parse(source_bytes).root_node
        caller_func = _find_treesitter_function(root, caller_label, source_bytes)
        if caller_func is None:
            return self._heuristic_bindings(active_taints, callee_params)

        expanded_taints = self._classic.expand_treesitter_taints(
            caller_id, caller_func, source_bytes, active_taints
        )

        call_label = edge.call_expression or callee_label.split(".")[-1]
        call_sites = _find_treesitter_calls(caller_func, call_label, callee_label, source_bytes)
        bindings: list[ParamBinding] = []
        param_by_index = {p["index"]: p["name"] for p in callee_params}
        for call in call_sites:
            args = _treesitter_call_arguments(call)
            for arg_index, arg in enumerate(args):
                callee_param = param_by_index.get(arg_index)
                if not callee_param:
                    continue
                for taint in expanded_taints:
                    if not _treesitter_expr_uses_name(arg, taint, source_bytes):
                        continue
                    if arg.type == "identifier":
                        arg_name = _node_text(arg, source_bytes)
                        call_line = call.start_point[0] + 1
                        if not self._classic.is_live_at_line(caller_id, arg_name, call_line):
                            continue
                    bindings.append(
                        ParamBinding(
                            caller_taint=taint,
                            callee_param=callee_param,
                            provenance=Provenance.EXTRACTED,
                            confidence=1.0,
                            line=call.start_point[0] + 1,
                        )
                    )
        if bindings:
            return _dedupe_bindings(bindings)
        return self._heuristic_bindings(active_taints, callee_params)


def _split_node_id(node_id: str) -> tuple[str, str, str]:
    """Split a node identifier into its file path, qualified path, and label.
    
    Parameters:
    	node_id (str): Node identifier containing an optional ``::`` separator.
    
    Returns:
    	tuple[str, str, str]: The file path, qualified file path, and node label.
    """
    if "::" not in node_id:
        return node_id, "", node_id
    file_path, label = node_id.split("::", 1)
    return file_path, file_path, label


def _find_python_function(tree: ast.Module, label: str) -> ast.FunctionDef | None:
    """Locate a top-level function or class method by its label.
    
    Parameters:
        tree (ast.Module): Parsed Python module to search.
        label (str): Function name or class-qualified method name.
    
    Returns:
        ast.FunctionDef | None: The matching function definition, or None if no match is found.
    """
    if "." in label:
        class_name, method_name = label.rsplit(".", 1)
        for node in tree.body:
            if isinstance(node, ast.ClassDef) and node.name == class_name:
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        if item.name == method_name:
                            return item
        return None

    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == label:
            return node
    return None


def _find_python_calls(
    func_node: ast.FunctionDef,
    call_label: str,
    callee_label: str,
) -> list[ast.Call]:
    """Find Python call expressions that match a callee label or its qualified name."""
    short = callee_label.split(".")[-1]
    matches: list[ast.Call] = []
    for node in ast.walk(func_node):
        if not isinstance(node, ast.Call):
            continue
        name = _python_call_name(node)
        if name in {call_label, callee_label, short}:
            matches.append(node)
        elif name.endswith(f".{short}"):
            matches.append(node)
    return matches


def _arg_carries_taint(arg: ast.AST, taint_name: str) -> bool:
    """Determine whether an expression references a tainted name.
    
    Parameters:
    	arg (ast.AST): The expression to inspect.
    	taint_name (str): The name associated with the taint.
    
    Returns:
    	bool: `true` if the expression references the tainted name, `false` otherwise.
    """
    return _expr_uses_name(arg, taint_name)


def _dedupe_bindings(bindings: list[ParamBinding]) -> list[ParamBinding]:
    """
    Remove duplicate bindings with the same caller taint and callee parameter.
    
    Parameters:
    	bindings (list[ParamBinding]): Bindings to deduplicate.
    
    Returns:
    	list[ParamBinding]: Bindings containing only the first occurrence of each caller-taint and callee-parameter pair.
    """
    seen: set[tuple[str, str]] = set()
    unique: list[ParamBinding] = []
    for binding in bindings:
        key = (binding.caller_taint, binding.callee_param)
        if key in seen:
            continue
        seen.add(key)
        unique.append(binding)
    return unique


def _node_text(node: Node, source_bytes: bytes) -> str:
    """
    Extract the UTF-8 source text represented by a Tree-sitter node.
    
    Parameters:
    	node (Node): The node whose source span identifies the text to extract.
    	source_bytes (bytes): The source file contents as UTF-8 encoded bytes.
    
    Returns:
    	str: The decoded source text for the node.
    """
    return source_bytes[node.start_byte : node.end_byte].decode("utf-8")


def _find_treesitter_function(root: Node, label: str, source_bytes: bytes) -> Node | None:
    """Locate a Tree-sitter function or class method by its label.
    
    Parameters:
        root (Node): Root node of the syntax tree to search.
        label (str): Function name or fully qualified class-and-method label.
        source_bytes (bytes): Source text used to resolve node names.
    
    Returns:
        Node | None: The matching function node, or None if no match is found.
    """
    if "." in label:
        class_name, method_name = label.rsplit(".", 1)
        class_node = _find_named_child(root, {"class_declaration", "class"}, class_name, source_bytes)
        if class_node is None:
            return None
        return _find_named_child(class_node, _TS_FUNC_TYPES, method_name, source_bytes)

    return _find_named_child(root, _TS_FUNC_TYPES, label, source_bytes)


def _find_named_child(
    root: Node,
    node_types: set[str],
    name: str,
    source_bytes: bytes,
) -> Node | None:
    """Find a named descendant node matching one of the specified node types.
    
    Parameters:
    	root (Node): The node whose descendants to search.
    	node_types (set[str]): Node types eligible for matching.
    	name (str): The expected name of the node.
    	source_bytes (bytes): Source bytes used to extract node names.
    
    Returns:
    	Node | None: The matching node, or `None` if no match is found.
    """
    stack = [root]
    while stack:
        node = stack.pop()
        if node.type in node_types:
            name_node = node.child_by_field_name("name")
            if name_node and _node_text(name_node, source_bytes) == name:
                return node
        stack.extend(node.children)
    return None


def _find_treesitter_calls(
    func_node: Node,
    call_label: str,
    callee_label: str,
    source_bytes: bytes,
) -> list[Node]:
    """
    Find Tree-sitter call nodes within a function that target the specified callee.
    
    Parameters:
    	func_node (Node): The function node to search.
    	call_label (str): The fully qualified caller-side call label.
    	callee_label (str): The callee label to match.
    	source_bytes (bytes): The source used to resolve call names.
    
    Returns:
    	list[Node]: Matching call nodes.
    """
    short = callee_label.split(".")[-1]
    matches: list[Node] = []
    stack = [func_node]
    while stack:
        node = stack.pop()
        if node.type in _TS_CALL_TYPES:
            name = _treesitter_call_name(node, source_bytes)
            if name in {call_label, callee_label, short} or name.endswith(f".{short}"):
                matches.append(node)
        stack.extend(node.children)
    return matches


def _treesitter_call_name(node: Node, source_bytes: bytes) -> str:
    """Extract the target name from a Tree-sitter call node.
    
    Parameters:
    	node (Node): Tree-sitter call node to inspect.
    	source_bytes (bytes): Source bytes used to resolve the node text.
    
    Returns:
    	str: The call target name, or an empty string when no target is present.
    """
    func = node.child_by_field_name("function") or node.child_by_field_name("name")
    if func is not None:
        return _node_text(func, source_bytes)
    return ""


def _treesitter_call_arguments(node: Node) -> list[Node]:
    """Return the argument nodes for a Tree-sitter call node, excluding delimiters."""
    args_node = node.child_by_field_name("arguments")
    if args_node is None:
        return []
    return [
        child
        for child in args_node.children
        if child.type not in {",", "(", ")", "[", "]"}
    ]


def _treesitter_expr_uses_name(node: Node, name: str, source_bytes: bytes) -> bool:
    """Determine whether a Tree-sitter expression contains an identifier with the given name.
    
    Parameters:
        node (Node): The root node of the expression to inspect.
        name (str): The identifier name to find.
        source_bytes (bytes): The source bytes used to extract identifier text.
    
    Returns:
        bool: `true` if the expression contains the specified identifier, `false` otherwise.
    """
    stack = [node]
    while stack:
        current = stack.pop()
        if current.type == "identifier" and _node_text(current, source_bytes) == name:
            return True
        stack.extend(current.children)
    return False
