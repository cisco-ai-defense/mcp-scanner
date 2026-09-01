# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Classic intraprocedural dataflow analyses wired into the code graph."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from tree_sitter import Node, Parser

from ..dataflow.available_expressions import AvailableExpressionsAnalyzer
from ..dataflow.liveness_analysis import LivenessAnalyzer
from ..dataflow.reaching_definitions import (
    Definition,
    ReachingDefinitionsAnalysis,
    ReachingDefsFact,
)
from ..dataflow.treesitter_classic import _iter_assignments as _ts_iter_assignments
from ..dataflow.treesitter_classic import analyze_treesitter_classic
from ..parser.python_parser import PythonParser
from ..parser.treesitter_parser import _get_language
from .cfg_fusion import _find_python_function, _find_treesitter_function, _split_node_id
from .models import CodeGraph

TREESITTER_LANGS = frozenset(
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


@dataclass
class ClassicDataflowSummary:
    """Results from reaching-defs, liveness, and available-expressions."""

    parameter_influenced: set[str] = field(default_factory=set)
    parameter_live: set[str] = field(default_factory=set)
    parameter_expressions: set[str] = field(default_factory=set)
    dead_assignment_lines: list[int] = field(default_factory=list)
    dead_variables: set[str] = field(default_factory=set)
    engine: str = "python"

    def to_dict(self) -> dict[str, Any]:
        return {
            "parameter_influenced": sorted(self.parameter_influenced),
            "parameter_live": sorted(self.parameter_live),
            "parameter_expressions": sorted(self.parameter_expressions),
            "dead_assignment_lines": list(self.dead_assignment_lines),
            "dead_variables": sorted(self.dead_variables),
            "engine": self.engine,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ClassicDataflowSummary:
        return cls(
            parameter_influenced=set(data.get("parameter_influenced") or []),
            parameter_live=set(data.get("parameter_live") or []),
            parameter_expressions=set(data.get("parameter_expressions") or []),
            dead_assignment_lines=list(data.get("dead_assignment_lines") or []),
            dead_variables=set(data.get("dead_variables") or []),
            engine=str(data.get("engine") or "python"),
        )


def _normalize_language(language: str) -> str:
    lang = (language or "python").lower()
    if lang == "c#":
        return "c_sharp"
    return lang


def _treesitter_parse_language(language: str) -> str:
    lang = _normalize_language(language)
    if lang == "tsx":
        return "typescript"
    return lang


def _node_text(node: Node, source_bytes: bytes) -> str:
    return source_bytes[node.start_byte : node.end_byte].decode("utf-8")


def _expr_uses_any(expr: ast.AST, names: set[str]) -> bool:
    for node in ast.walk(expr):
        if isinstance(node, ast.Name) and node.id in names:
            return True
    return False


def _treesitter_expr_uses_any(node: Node, names: set[str], source_bytes: bytes) -> bool:
    stack = [node]
    while stack:
        current = stack.pop()
        if current.type == "identifier" and _node_text(current, source_bytes) in names:
            return True
        stack.extend(current.children)
    return False


def _treesitter_target_name(node: Node, source_bytes: bytes) -> str | None:
    if node.type == "identifier":
        return _node_text(node, source_bytes)
    name = node.child_by_field_name("name")
    if name is not None:
        if name.type == "identifier":
            return _node_text(name, source_bytes)
        return _treesitter_target_name(name, source_bytes)
    left = node.child_by_field_name("left")
    if left is not None:
        return _treesitter_target_name(left, source_bytes)
    return None


def _treesitter_value_node(node: Node) -> Node | None:
    value = node.child_by_field_name("value") or node.child_by_field_name("right")
    if value is not None:
        return value
    for child in node.children:
        if child.type in {
            "=",
            ":=",
            "let",
            "var",
            "const",
            "identifier",
            ",",
            "(",
            ")",
        }:
            continue
        return child
    return None


def _iter_treesitter_assignments(
    func_node: Node, source_bytes: bytes
) -> list[tuple[str, Node]]:
    """Return ``(target_name, value_node)`` pairs from a function body."""
    pairs: list[tuple[str, Node]] = []
    stack = [func_node]
    while stack:
        node = stack.pop()
        if node.type == "variable_declarator":
            target = _treesitter_target_name(node, source_bytes)
            value = _treesitter_value_node(node)
            if target and value is not None:
                pairs.append((target, value))
        elif node.type in ("assignment_expression", "assignment"):
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is not None and right is not None:
                target = _treesitter_target_name(left, source_bytes)
                if target:
                    pairs.append((target, right))
        elif node.type in (
            "lexical_declaration",
            "variable_declaration",
            "local_variable_declaration",
            "local_declaration_statement",
            "let_declaration",
            "short_var_declaration",
            "property_declaration",
        ):
            for child in node.children:
                if child.type == "variable_declarator":
                    name_node = child.child_by_field_name("name")
                    value = _treesitter_value_node(child)
                    if name_node is not None and value is not None:
                        target = _treesitter_target_name(name_node, source_bytes)
                        if target:
                            pairs.append((target, value))
        stack.extend(node.children)
    return pairs


def collect_assignment_aliases(func_node: ast.AST, root: str) -> set[str]:
    """Transitively collect simple assignment aliases of ``root``."""
    aliases = {root}
    changed = True
    while changed:
        changed = False
        for node in ast.walk(func_node):
            if not isinstance(node, ast.Assign):
                continue
            for target in node.targets:
                if not isinstance(target, ast.Name):
                    continue
                if target.id in aliases:
                    continue
                if _expr_uses_any(node.value, aliases):
                    aliases.add(target.id)
                    changed = True
    return aliases


def collect_treesitter_assignment_aliases(
    func_node: Node,
    source_bytes: bytes,
    root: str,
) -> set[str]:
    """Transitively collect simple assignment aliases of ``root``."""
    aliases = {root}
    changed = True
    while changed:
        changed = False
        for target, value in _iter_treesitter_assignments(func_node, source_bytes):
            if target in aliases:
                continue
            if _treesitter_expr_uses_any(value, aliases, source_bytes):
                aliases.add(target)
                changed = True
    return aliases


def _run_reaching_definitions(
    parser: PythonParser,
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    parameter_names: list[str],
) -> ReachingDefinitionsAnalysis:
    analysis = ReachingDefinitionsAnalysis(parser, parameter_names)
    analysis.build_cfg_for_function(func_node)

    initial_fact = ReachingDefsFact()
    for param_name in parameter_names:
        initial_fact.defs.add(
            Definition(var=param_name, node_id=-1, is_parameter=True)
        )

    analysis.analyze(initial_fact)
    analysis._compute_use_def_chains()
    return analysis


def _run_liveness(
    parser: PythonParser,
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    parameter_names: list[str],
) -> LivenessAnalyzer:
    analysis = LivenessAnalyzer(parser, parameter_names)
    analysis.build_cfg_for_function(func_node)
    analysis.analyze_liveness()
    return analysis


def _run_available_expressions(
    parser: PythonParser,
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    parameter_names: list[str],
) -> AvailableExpressionsAnalyzer:
    analysis = AvailableExpressionsAnalyzer(parser, parameter_names)
    analysis.build_cfg_for_function(func_node)
    analysis.analyze_available_exprs()
    return analysis


def analyze_python_function(
    source: str,
    file_path: str,
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    parameter_names: list[str],
) -> ClassicDataflowSummary:
    """Run classic dataflow analyses for one Python function."""
    parser = PythonParser(Path(file_path), source)
    reaching = _run_reaching_definitions(parser, func_node, parameter_names)
    liveness = _run_liveness(parser, func_node, parameter_names)
    available = _run_available_expressions(parser, func_node, parameter_names)

    dead_lines: list[int] = []
    dead_vars: set[str] = set()
    for node in liveness.dead_code:
        line = getattr(node.ast_node, "lineno", None)
        if isinstance(line, int):
            dead_lines.append(line)
        if isinstance(node.ast_node, ast.Assign):
            for target in node.ast_node.targets:
                if isinstance(target, ast.Name):
                    dead_vars.add(target.id)

    return ClassicDataflowSummary(
        parameter_influenced=reaching.get_parameter_influenced_vars(),
        parameter_live=liveness.get_parameter_live_vars(),
        parameter_expressions=available.get_parameter_expressions(),
        dead_assignment_lines=sorted(set(dead_lines)),
        dead_variables=dead_vars,
        engine="python",
    )


def analyze_treesitter_function(
    language: str,
    func_node: Node,
    parameter_names: list[str],
    source_bytes: bytes,
) -> ClassicDataflowSummary:
    """Run classic dataflow trio for one tree-sitter function."""
    reaching, liveness, available = analyze_treesitter_classic(
        language, func_node, parameter_names, source_bytes
    )

    dead_lines: list[int] = []
    dead_vars: set[str] = set()
    for node in liveness.dead_code:
        dead_lines.append(node.ast_node.start_point[0] + 1)
        for target, _ in _ts_iter_assignments(node.ast_node, source_bytes):
            dead_vars.add(target)

    return ClassicDataflowSummary(
        parameter_influenced=reaching.get_parameter_influenced_vars(),
        parameter_live=liveness.get_parameter_live_vars(),
        parameter_expressions=available.get_parameter_expressions(),
        dead_assignment_lines=sorted(set(dead_lines)),
        dead_variables=dead_vars,
        engine="treesitter_classic",
    )


class ClassicDataflowEngine:
    """Cache and expose classic dataflow facts for graph nodes."""

    def __init__(self, graph: CodeGraph) -> None:
        self._graph = graph
        self._cache: dict[str, ClassicDataflowSummary] = {}

    def enrich_graph(self) -> None:
        """Run classic analyses and store summaries on supported function nodes."""
        for node_id, node in self._graph.nodes.items():
            language = _normalize_language(node.language or self._graph.language or "python")
            if language != "python" and language not in TREESITTER_LANGS:
                continue
            summary = self.get_summary(node_id)
            if summary is not None:
                node.metadata["classic_dataflow"] = summary.to_dict()

    def get_summary(self, node_id: str) -> ClassicDataflowSummary | None:
        if node_id in self._cache:
            return self._cache[node_id]

        if node_id not in self._graph.nodes:
            return None

        node = self._graph.nodes[node_id]
        existing = node.metadata.get("classic_dataflow")
        if isinstance(existing, dict):
            summary = ClassicDataflowSummary.from_dict(existing)
            self._cache[node_id] = summary
            return summary

        language = _normalize_language(node.language or self._graph.language or "python")
        caller_file, _, caller_label = _split_node_id(node_id)
        source = self._graph.source_registry.get(caller_file)
        if not source:
            return None

        params = [
            p["name"]
            for p in (node.metadata.get("parameters") or [])
            if isinstance(p, dict) and p.get("name")
        ]

        if language == "python":
            summary = self._analyze_python(caller_file, caller_label, source, params)
        elif language in TREESITTER_LANGS:
            summary = self._analyze_treesitter(
                language, caller_file, caller_label, source, params
            )
        else:
            return None

        if summary is not None:
            self._cache[node_id] = summary
        return summary

    def _analyze_python(
        self,
        caller_file: str,
        caller_label: str,
        source: str,
        params: list[str],
    ) -> ClassicDataflowSummary | None:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return None

        func_node = _find_python_function(tree, caller_label)
        if func_node is None:
            return None

        if not params:
            params = [arg.arg for arg in func_node.args.args if arg.arg != "self"]

        return analyze_python_function(source, caller_file, func_node, params)

    def _analyze_treesitter(
        self,
        language: str,
        caller_file: str,
        caller_label: str,
        source: str,
        params: list[str],
    ) -> ClassicDataflowSummary | None:
        ts_lang = _treesitter_parse_language(language)
        ts_language = _get_language(ts_lang)
        if ts_language is None:
            return None

        source_bytes = source.encode("utf-8")
        root = Parser(ts_language).parse(source_bytes).root_node
        func_node = _find_treesitter_function(root, caller_label, source_bytes)
        if func_node is None:
            return None

        if not params:
            params = self._treesitter_param_names(func_node, source_bytes)

        return analyze_treesitter_function(language, func_node, params, source_bytes)

    @staticmethod
    def _treesitter_param_names(func_node: Node, source_bytes: bytes) -> list[str]:
        params_node = func_node.child_by_field_name("parameters") or func_node.child_by_field_name(
            "formal_parameters"
        )
        if params_node is None:
            return []
        names: list[str] = []
        for child in params_node.children:
            if child.type in {",", "(", ")", "[", "]"}:
                continue
            name_node = child.child_by_field_name("name")
            if name_node is None and child.type == "identifier":
                name_node = child
            if name_node is None:
                for sub in child.children:
                    if sub.type == "identifier":
                        name_node = sub
                        break
            if name_node is None:
                continue
            name = _node_text(name_node, source_bytes)
            if name and name not in {"self", "this"}:
                names.append(name)
        return names

    def aliases_of(
        self,
        node_id: str,
        func_node: ast.AST,
        root: str,
    ) -> set[str]:
        """Return assignment aliases of ``root`` within a Python function."""
        summary = self.get_summary(node_id)
        aliases = collect_assignment_aliases(func_node, root)
        if summary:
            aliases &= summary.parameter_influenced | {root}
        return aliases

    def treesitter_aliases_of(
        self,
        node_id: str,
        func_node: Node,
        source_bytes: bytes,
        root: str,
    ) -> set[str]:
        """Return assignment aliases of ``root`` within a tree-sitter function."""
        summary = self.get_summary(node_id)
        aliases = collect_treesitter_assignment_aliases(func_node, source_bytes, root)
        if summary:
            aliases &= summary.parameter_influenced | {root}
        return aliases

    def expand_active_taints(
        self,
        node_id: str,
        func_node: ast.AST,
        active_taints: set[str],
    ) -> set[str]:
        """Expand active taints with parameter-influenced assignment aliases."""
        expanded = set(active_taints)
        for taint in active_taints:
            expanded.update(self.aliases_of(node_id, func_node, taint))
        return expanded

    def expand_treesitter_taints(
        self,
        node_id: str,
        func_node: Node,
        source_bytes: bytes,
        active_taints: set[str],
    ) -> set[str]:
        """Expand active taints for tree-sitter functions."""
        expanded = set(active_taints)
        for taint in active_taints:
            expanded.update(
                self.treesitter_aliases_of(node_id, func_node, source_bytes, taint)
            )
        return expanded

    def is_live_at_line(self, node_id: str, var: str, line: int) -> bool:
        """True when a parameter-influenced variable is live at ``line``."""
        summary = self.get_summary(node_id)
        if summary is None:
            return True
        if var not in summary.parameter_influenced:
            return True
        if var in summary.dead_variables:
            return False
        if line in summary.dead_assignment_lines:
            return False
        return var in summary.parameter_live or var in summary.parameter_influenced
