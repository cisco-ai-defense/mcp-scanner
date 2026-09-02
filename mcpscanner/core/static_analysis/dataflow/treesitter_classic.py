# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Classic reaching-defs, liveness, and available-expressions on tree-sitter CFGs."""

from __future__ import annotations

import re
import time
from typing import Generic, TypeVar

from tree_sitter import Node

from ..cfg.treesitter_builder import TreeSitterCFG, TreeSitterCFGBuilder, TSCFGNode
from .available_expressions import AvailableExprsFact
from .liveness_analysis import LivenessFact
from .reaching_definitions import Definition, ReachingDefsFact
from ....utils.logging_config import get_logger

logger = get_logger(__name__)

T = TypeVar("T")

_ASSIGNMENT_STMT_TYPES = frozenset(
    {
        "variable_declarator",
        "assignment_expression",
        "assignment",
        "augmented_assignment_expression",
        "short_var_declaration",
        "let_declaration",
        "lexical_declaration",
        "variable_declaration",
        "local_variable_declaration",
        "local_declaration_statement",
        "property_declaration",
        "expression_statement",
    }
)

_CALL_TYPES = frozenset(
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

_EXPR_GEN_TYPES = frozenset(
    {
        "binary_expression",
        "call_expression",
        "member_expression",
        "subscript_expression",
        "unary_expression",
        "update_expression",
        "parenthesized_expression",
        "template_string",
        "string",
        "concatenated_string",
        "additive_expression",
        "multiplicative_expression",
    }
)


def _node_text(node: Node, source_bytes: bytes) -> str:
    return source_bytes[node.start_byte : node.end_byte].decode("utf-8")


def _normalize_language(language: str) -> str:
    lang = (language or "javascript").lower()
    if lang == "tsx":
        return "typescript"
    if lang == "c#":
        return "c_sharp"
    return lang


def _target_name(node: Node, source_bytes: bytes) -> str | None:
    if node.type == "identifier":
        return _node_text(node, source_bytes)
    name = node.child_by_field_name("name")
    if name is not None:
        return _target_name(name, source_bytes)
    left = node.child_by_field_name("left")
    if left is not None:
        return _target_name(left, source_bytes)
    return None


def _value_node(node: Node) -> Node | None:
    return node.child_by_field_name("value") or node.child_by_field_name("right")


def _iter_assignments(stmt: Node, source_bytes: bytes) -> list[tuple[str, Node]]:
    """Extract ``(target, value)`` pairs from a CFG statement node."""
    pairs: list[tuple[str, Node]] = []

    def add_pair(target_node: Node | None, value: Node | None) -> None:
        if target_node is None or value is None:
            return
        name = _target_name(target_node, source_bytes)
        if name:
            pairs.append((name, value))

    if stmt.type == "variable_declarator":
        add_pair(stmt.child_by_field_name("name"), _value_node(stmt))
    elif stmt.type in ("assignment_expression", "assignment", "augmented_assignment_expression"):
        add_pair(stmt.child_by_field_name("left"), stmt.child_by_field_name("right"))
    elif stmt.type in (
        "lexical_declaration",
        "variable_declaration",
        "local_variable_declaration",
        "local_declaration_statement",
        "short_var_declaration",
        "let_declaration",
        "property_declaration",
    ):
        for child in stmt.children:
            if child.type == "variable_declarator":
                add_pair(child.child_by_field_name("name"), _value_node(child))
    elif stmt.type == "expression_statement":
        for child in stmt.children:
            if child.type in ("assignment_expression", "assignment", "augmented_assignment_expression"):
                add_pair(child.child_by_field_name("left"), child.child_by_field_name("right"))
    elif stmt.type in ("for_statement", "for_in_statement", "enhanced_for_statement", "foreach_statement"):
        init = stmt.child_by_field_name("initializer") or stmt.child_by_field_name("left")
        if init is not None:
            pairs.extend(_iter_assignments(init, source_bytes))
        body_target = stmt.child_by_field_name("left") or stmt.child_by_field_name("name")
        iterable = (
            stmt.child_by_field_name("right")
            or stmt.child_by_field_name("collection")
            or stmt.child_by_field_name("value")
        )
        if body_target is not None and iterable is not None:
            add_pair(body_target, iterable)

    return pairs


def _collect_identifiers(node: Node, source_bytes: bytes, *, skip: set[str] | None = None) -> set[str]:
    skip = skip or set()
    found: set[str] = set()
    stack = [node]
    while stack:
        current = stack.pop()
        if current.type == "identifier":
            name = _node_text(current, source_bytes)
            if name and name not in skip:
                found.add(name)
        stack.extend(current.children)
    return found


def _expr_uses_parameters(expr: Node, source_bytes: bytes, fact: ReachingDefsFact) -> bool:
    for name in _collect_identifiers(expr, source_bytes):
        reaching = [d for d in fact.defs if d.var == name]
        if any(d.is_parameter for d in reaching):
            return True
    return False


def _normalize_expr(node: Node, source_bytes: bytes) -> str:
    text = _node_text(node, source_bytes).strip()
    return text[:200] if text else ""


def _expr_uses_vars(expr_str: str, variable_names: set[str]) -> bool:
    for var in variable_names:
        if re.search(rf"\b{re.escape(var)}\b", expr_str):
            return True
    return False


class TreeSitterDataFlowAnalyzer(Generic[T]):
    """Generic worklist dataflow engine over a tree-sitter CFG."""

    def __init__(
        self,
        language: str,
        function_node: Node,
        source_bytes: bytes,
        parameter_names: list[str],
    ) -> None:
        self.language = _normalize_language(language)
        self.function_node = function_node
        self.source_bytes = source_bytes
        self.parameter_names = list(parameter_names)
        self.cfg: TreeSitterCFG = TreeSitterCFGBuilder(self.language).build(function_node)
        self.in_facts: dict[int, T] = {}
        self.out_facts: dict[int, T] = {}

    def _is_pseudo(self, node: TSCFGNode) -> bool:
        return node.label in {"ENTRY", "EXIT"}

    def analyze(self, initial_fact: T, *, forward: bool = True) -> None:
        analyze_start = time.perf_counter()
        analysis_name = type(self).__name__

        for node in self.cfg.nodes:
            self.in_facts[node.node_id] = self._copy_fact(initial_fact)
            self.out_facts[node.node_id] = self._copy_fact(initial_fact)

        worklist = [node for node in self.cfg.nodes if not self._is_pseudo(node)]
        in_worklist = {node.node_id for node in worklist}
        iteration_count = 0
        max_iterations = max(len(self.cfg.nodes) * 100, 1)
        capped = False

        while worklist:
            iteration_count += 1
            if iteration_count > max_iterations:
                capped = True
                break

            node = worklist.pop(0)
            in_worklist.discard(node.node_id)

            if forward:
                pred_facts = [
                    self.out_facts[pred.node_id]
                    for pred in node.predecessors
                    if not self._is_pseudo(pred)
                ]
                in_fact = self.merge(pred_facts) if pred_facts else self._copy_fact(initial_fact)
                self.in_facts[node.node_id] = in_fact
                out_fact = self.transfer(node, in_fact)
                if not self._facts_equal(out_fact, self.out_facts[node.node_id]):
                    self.out_facts[node.node_id] = out_fact
                    for succ in node.successors:
                        if succ.node_id not in in_worklist and not self._is_pseudo(succ):
                            worklist.append(succ)
                            in_worklist.add(succ.node_id)
            else:
                succ_facts = [
                    self.in_facts[succ.node_id]
                    for succ in node.successors
                    if not self._is_pseudo(succ)
                ]
                out_fact = self.merge(succ_facts) if succ_facts else self._copy_fact(initial_fact)
                self.out_facts[node.node_id] = out_fact
                in_fact = self.transfer(node, out_fact)
                if not self._facts_equal(in_fact, self.in_facts[node.node_id]):
                    self.in_facts[node.node_id] = in_fact
                    for pred in node.predecessors:
                        if pred.node_id not in in_worklist and not self._is_pseudo(pred):
                            worklist.append(pred)
                            in_worklist.add(pred.node_id)

        logger.debug(
            "static_dataflow treesitter_classic %s language=%s nodes=%d iterations=%d "
            "direction=%s capped=%s duration_us=%d",
            analysis_name,
            self.language,
            len(self.cfg.nodes),
            iteration_count,
            "forward" if forward else "backward",
            capped,
            int((time.perf_counter() - analyze_start) * 1_000_000),
        )

    def transfer(self, node: TSCFGNode, fact: T) -> T:
        raise NotImplementedError

    def merge(self, facts: list[T]) -> T:
        raise NotImplementedError

    def _copy_fact(self, fact: T) -> T:
        if hasattr(fact, "copy"):
            return fact.copy()  # type: ignore[no-any-return]
        return fact

    def _facts_equal(self, left: T, right: T) -> bool:
        return left == right


class TreeSitterReachingDefinitions(TreeSitterDataFlowAnalyzer[ReachingDefsFact]):
    """Reaching definitions on tree-sitter CFG nodes."""

    def __init__(
        self,
        language: str,
        function_node: Node,
        source_bytes: bytes,
        parameter_names: list[str],
    ) -> None:
        super().__init__(language, function_node, source_bytes, parameter_names)
        self.use_def_chains: dict[tuple[int, str], list[Definition]] = {}

    def analyze_reaching_defs(self) -> dict[tuple[int, str], list[Definition]]:
        initial = ReachingDefsFact()
        for param in self.parameter_names:
            initial.defs.add(Definition(var=param, node_id=-1, is_parameter=True))
        self.analyze(initial, forward=True)
        self._compute_use_def_chains()
        return self.use_def_chains

    def transfer(self, node: TSCFGNode, in_fact: ReachingDefsFact) -> ReachingDefsFact:
        out_fact = in_fact.copy()
        if self._is_pseudo(node):
            return out_fact

        ast_node = node.ast_node
        for target, value in _iter_assignments(ast_node, self.source_bytes):
            uses_param = _expr_uses_parameters(value, self.source_bytes, out_fact)
            if target in {d.var for d in out_fact.defs if d.is_parameter}:
                uses_param = True
            out_fact.defs = {d for d in out_fact.defs if d.var != target}
            out_fact.defs.add(
                Definition(
                    var=target,
                    node_id=node.node_id,
                    is_parameter=uses_param,
                )
            )

        if ast_node.type in _CALL_TYPES:
            pass

        return out_fact

    def merge(self, facts: list[ReachingDefsFact]) -> ReachingDefsFact:
        if not facts:
            return ReachingDefsFact()
        merged = ReachingDefsFact()
        for fact in facts:
            merged.defs.update(fact.defs)
        return merged

    def _compute_use_def_chains(self) -> None:
        for node in self.cfg.nodes:
            if self._is_pseudo(node):
                continue
            reaching = self.in_facts.get(node.node_id, ReachingDefsFact())
            uses = _collect_identifiers(node.ast_node, self.source_bytes)
            for var in uses:
                reaching_defs = [d for d in reaching.defs if d.var == var]
                self.use_def_chains[(node.node_id, var)] = reaching_defs

    def get_parameter_influenced_vars(self) -> set[str]:
        influenced: set[str] = set(self.parameter_names)
        for (_node_id, var), defs in self.use_def_chains.items():
            if any(d.is_parameter for d in defs):
                influenced.add(var)
        for fact in self.out_facts.values():
            for definition in fact.defs:
                if definition.is_parameter:
                    influenced.add(definition.var)
        return influenced


class TreeSitterLivenessAnalyzer(TreeSitterDataFlowAnalyzer[LivenessFact]):
    """Backward liveness with MCP parameter tracking."""

    def __init__(
        self,
        language: str,
        function_node: Node,
        source_bytes: bytes,
        parameter_names: list[str],
    ) -> None:
        super().__init__(language, function_node, source_bytes, parameter_names)
        self.param_influenced: set[str] = set(parameter_names)
        self.dead_code: list[TSCFGNode] = []

    def analyze_liveness(self) -> dict[int, set[str]]:
        self.analyze(LivenessFact(), forward=False)
        self._detect_dead_code()
        return {
            node_id: fact.live_vars for node_id, fact in self.in_facts.items()
        }

    def transfer(self, node: TSCFGNode, out_fact: LivenessFact) -> LivenessFact:
        in_fact = out_fact.copy()
        if self._is_pseudo(node):
            return in_fact

        ast_node = node.ast_node
        for target, value in _iter_assignments(ast_node, self.source_bytes):
            in_fact.live_vars.discard(target)
            in_fact.param_influenced_live.discard(target)
            used = _collect_identifiers(value, self.source_bytes)
            in_fact.live_vars.update(used)
            param_used = used & self.param_influenced
            in_fact.param_influenced_live.update(param_used)
            if param_used:
                self.param_influenced.add(target)

        self._gen_uses_from_node(ast_node, in_fact)

        return in_fact

    def _gen_uses_from_node(self, ast_node: Node, in_fact: LivenessFact) -> None:
        if ast_node.type in ("return_statement", "return_expression", "return"):
            for child in ast_node.children:
                if child.type not in {"return", ";", "keyword"}:
                    used = _collect_identifiers(child, self.source_bytes)
                    in_fact.live_vars.update(used)
                    in_fact.param_influenced_live.update(used & self.param_influenced)
                    return

        if ast_node.type in _CALL_TYPES:
            used = _collect_identifiers(ast_node, self.source_bytes)
            in_fact.live_vars.update(used)
            in_fact.param_influenced_live.update(used & self.param_influenced)
            return

        if ast_node.type in ("if_statement", "if_expression", "if", "while_statement", "while_expression", "while"):
            test = ast_node.child_by_field_name("condition") or ast_node.child_by_field_name("test")
            if test is not None:
                used = _collect_identifiers(test, self.source_bytes)
                in_fact.live_vars.update(used)
                in_fact.param_influenced_live.update(used & self.param_influenced)
            return

        if ast_node.type in ("expression_statement", "lexical_declaration", "variable_declaration"):
            for child in ast_node.children:
                if child.type in _CALL_TYPES:
                    used = _collect_identifiers(child, self.source_bytes)
                    in_fact.live_vars.update(used)
                    in_fact.param_influenced_live.update(used & self.param_influenced)
                elif child.type == "variable_declarator":
                    value = _value_node(child)
                    if value is not None and value.type in _CALL_TYPES:
                        used = _collect_identifiers(value, self.source_bytes)
                        in_fact.live_vars.update(used)
                        in_fact.param_influenced_live.update(used & self.param_influenced)

    def merge(self, facts: list[LivenessFact]) -> LivenessFact:
        if not facts:
            return LivenessFact()
        merged = LivenessFact()
        for fact in facts:
            merged.live_vars.update(fact.live_vars)
            merged.param_influenced_live.update(fact.param_influenced_live)
        return merged

    def _detect_dead_code(self) -> None:
        for node in self.cfg.nodes:
            if self._is_pseudo(node):
                continue
            live_after = self.out_facts.get(node.node_id, LivenessFact())
            for target, _value in _iter_assignments(node.ast_node, self.source_bytes):
                if target not in live_after.live_vars:
                    self.dead_code.append(node)

    def get_parameter_live_vars(self) -> set[str]:
        return self.param_influenced.copy()


class TreeSitterAvailableExpressions(TreeSitterDataFlowAnalyzer[AvailableExprsFact]):
    """Forward available-expressions with MCP parameter tracking."""

    def __init__(
        self,
        language: str,
        function_node: Node,
        source_bytes: bytes,
        parameter_names: list[str],
    ) -> None:
        super().__init__(language, function_node, source_bytes, parameter_names)
        self.param_influenced: set[str] = set(parameter_names)

    def analyze_available_exprs(self) -> dict[int, set[str]]:
        self.analyze(AvailableExprsFact(), forward=True)
        return {
            node_id: fact.available for node_id, fact in self.out_facts.items()
        }

    def transfer(self, node: TSCFGNode, in_fact: AvailableExprsFact) -> AvailableExprsFact:
        out_fact = in_fact.copy()
        if self._is_pseudo(node):
            return out_fact

        ast_node = node.ast_node
        for target, value in _iter_assignments(ast_node, self.source_bytes):
            assigned = {target}
            out_fact.available = {
                expr for expr in out_fact.available if not _expr_uses_vars(expr, assigned)
            }
            out_fact.param_exprs = {
                expr for expr in out_fact.param_exprs if not _expr_uses_vars(expr, assigned)
            }
            if value.type in _EXPR_GEN_TYPES or value.type in _CALL_TYPES:
                expr_str = _normalize_expr(value, self.source_bytes)
                if expr_str:
                    out_fact.available.add(expr_str)
                    if _expr_uses_vars(expr_str, self.param_influenced):
                        out_fact.param_exprs.add(expr_str)
                        self.param_influenced.add(target)

        if ast_node.type in _CALL_TYPES:
            out_fact.available.clear()
            out_fact.param_exprs.clear()

        return out_fact

    def merge(self, facts: list[AvailableExprsFact]) -> AvailableExprsFact:
        if not facts:
            return AvailableExprsFact()
        merged = facts[0].copy()
        for fact in facts[1:]:
            merged.available &= fact.available
            merged.param_exprs &= fact.param_exprs
        return merged

    def get_parameter_expressions(self) -> set[str]:
        all_exprs: set[str] = set()
        for fact in self.out_facts.values():
            all_exprs.update(fact.param_exprs)
        return all_exprs


def analyze_treesitter_classic(
    language: str,
    function_node: Node,
    parameter_names: list[str],
    source_bytes: bytes,
) -> tuple[TreeSitterReachingDefinitions, TreeSitterLivenessAnalyzer, TreeSitterAvailableExpressions]:
    """Run reaching-defs, liveness, and available-expressions for one function."""
    reaching = TreeSitterReachingDefinitions(language, function_node, source_bytes, parameter_names)
    reaching.analyze_reaching_defs()

    liveness = TreeSitterLivenessAnalyzer(language, function_node, source_bytes, parameter_names)
    liveness.analyze_liveness()

    available = TreeSitterAvailableExpressions(language, function_node, source_bytes, parameter_names)
    available.analyze_available_exprs()

    return reaching, liveness, available
