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
    """
    Extract the UTF-8 source text covered by a syntax tree node.
    
    Parameters:
    	node (Node): The syntax tree node whose source span is extracted.
    	source_bytes (bytes): The complete source code as UTF-8 encoded bytes.
    
    Returns:
    	str: The decoded source text for the node's byte range.
    """
    return source_bytes[node.start_byte : node.end_byte].decode("utf-8")


def _normalize_language(language: str) -> str:
    """
    Normalize a language name for tree-sitter grammar lookup.
    
    Parameters:
    	language (str): The language name to normalize.
    
    Returns:
    	str: The normalized language name.
    """
    lang = (language or "javascript").lower()
    if lang == "tsx":
        return "typescript"
    if lang == "c#":
        return "c_sharp"
    return lang


def _target_name(node: Node, source_bytes: bytes) -> str | None:
    """
    Extract the assigned identifier name from a syntax tree node.
    
    Parameters:
        node (Node): Syntax tree node representing an assignment target.
        source_bytes (bytes): Source code used to extract identifier text.
    
    Returns:
        str | None: The identifier name, or None if the node does not contain one.
    """
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
        """Add an assignment target and value pair when both nodes resolve to a target name."""
        if target_node is None or value is None:
            return
        name = _target_name(target_node, source_bytes)
        if name:
            pairs.append((name, value))

    if stmt.type == "variable_declarator":
        add_pair(stmt.child_by_field_name("name"), _value_node(stmt))
    elif stmt.type in ("assignment_expression", "assignment", "assignment_statement"):
        add_pair(stmt.child_by_field_name("left"), stmt.child_by_field_name("right"))
    elif stmt.type == "augmented_assignment_expression":
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
    """
    Collect identifier names from a syntax tree node.
    
    Parameters:
        node (Node): Root node of the syntax tree to inspect.
        source_bytes (bytes): Source text used to extract identifier names.
        skip (set[str] | None): Identifier names to exclude.
    
    Returns:
        set[str]: Identifier names found in the node, excluding skipped names.
    """
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
    """
    Determine whether an expression references a variable with a parameter-originating reaching definition.
    
    Parameters:
    	expr (Node): Expression to inspect.
    	source_bytes (bytes): Source text used to extract identifiers from the expression.
    	fact (ReachingDefsFact): Reaching definitions used to identify parameter-originating variables.
    
    Returns:
    	bool: `True` if the expression uses a variable with a parameter-originating definition, `False` otherwise.
    """
    for name in _collect_identifiers(expr, source_bytes):
        reaching = [d for d in fact.defs if d.var == name]
        if any(d.is_parameter for d in reaching):
            return True
    return False


def _normalize_expr(node: Node, source_bytes: bytes) -> str:
    """
    Normalize an expression to a trimmed source-text representation.
    
    Parameters:
    	node (Node): The syntax tree node containing the expression.
    	source_bytes (bytes): Source bytes used to extract the node text.
    
    Returns:
    	str: The trimmed expression text, limited to 200 characters.
    """
    text = _node_text(node, source_bytes).strip()
    return text[:200] if text else ""


def _expr_uses_vars(expr_str: str, variable_names: set[str]) -> bool:
    for var in variable_names:
        pattern = (
            rf"(?<![A-Za-z0-9_$]){re.escape(var)}(?![A-Za-z0-9_$])"
        )
        if re.search(pattern, expr_str):
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
        """
        Initialize a data-flow analyzer for a function.
        
        Parameters:
            language (str): Programming language of the function.
            function_node (Node): Tree-sitter node representing the function.
            source_bytes (bytes): Source code containing the function.
            parameter_names (list[str]): Names of the function parameters.
        """
        self.language = _normalize_language(language)
        self.function_node = function_node
        self.source_bytes = source_bytes
        self.parameter_names = list(parameter_names)
        self.cfg: TreeSitterCFG = TreeSitterCFGBuilder(self.language).build(function_node)
        self.in_facts: dict[int, T] = {}
        self.out_facts: dict[int, T] = {}

    def _is_pseudo(self, node: TSCFGNode) -> bool:
        """Determine whether a control-flow graph node is an entry or exit pseudo-node.
        
        Parameters:
        	node (TSCFGNode): Control-flow graph node to classify.
        
        Returns:
        	bool: `true` if the node represents an entry or exit point, `false` otherwise.
        """
        return node.label in {"ENTRY", "EXIT"}

    def analyze(self, initial_fact: T, *, forward: bool = True) -> None:
        """
        Run the data-flow analysis over the control-flow graph.
        
        Parameters:
            initial_fact (T): Fact assigned to nodes without incoming facts.
            forward (bool): Whether to propagate facts from predecessors to successors.
        """
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
        """Apply the node-specific transfer operation to a dataflow fact.
        
        Parameters:
        	node (TSCFGNode): The control-flow graph node being analyzed.
        	fact (T): The incoming dataflow fact.
        
        Returns:
        	T: The transformed dataflow fact.
        
        Raises:
        	NotImplementedError: Always raised because subclasses must implement this operation.
        """
        raise NotImplementedError

    def merge(self, facts: list[T]) -> T:
        """
        Merge incoming data-flow facts into a single fact.
        
        Parameters:
        	facts (list[T]): Facts to combine.
        
        Raises:
        	NotImplementedError: Always raised because subclasses must define the merge operation.
        """
        raise NotImplementedError

    def _copy_fact(self, fact: T) -> T:
        """
        Create an independent copy of a data-flow fact when supported.
        
        Parameters:
            fact (T): The data-flow fact to copy.
        
        Returns:
            T: A copy of the fact, or the original fact when copying is unavailable.
        """
        if hasattr(fact, "copy"):
            return fact.copy()  # type: ignore[no-any-return]
        return fact

    def _facts_equal(self, left: T, right: T) -> bool:
        """Determine whether two data-flow facts are equal.
        
        Parameters:
        	left (T): The first fact to compare.
        	right (T): The second fact to compare.
        
        Returns:
        	bool: `true` if the facts are equal, `false` otherwise.
        """
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
        """Initialize the reaching-definitions analysis for a function."""
        super().__init__(language, function_node, source_bytes, parameter_names)
        self.use_def_chains: dict[tuple[int, str], list[Definition]] = {}

    def analyze_reaching_defs(self) -> dict[tuple[int, str], list[Definition]]:
        """
        Build use-definition chains from reaching-definitions analysis.
        
        Returns:
            dict[tuple[int, str], list[Definition]]: Definitions reaching each identifier use,
            keyed by control-flow node ID and variable name.
        """
        initial = ReachingDefsFact()
        for param in self.parameter_names:
            initial.defs.add(Definition(var=param, node_id=-1, is_parameter=True))
        self.analyze(initial, forward=True)
        self._compute_use_def_chains()
        return self.use_def_chains

    def transfer(self, node: TSCFGNode, in_fact: ReachingDefsFact) -> ReachingDefsFact:
        """Update reaching definitions for assignments in a control-flow graph node.
        
        Parameters:
        	node (TSCFGNode): The control-flow graph node being processed.
        	in_fact (ReachingDefsFact): Reaching definitions entering the node.
        
        Returns:
        	ReachingDefsFact: The definitions reaching the node after applying its assignments.
        """
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
        """
        Merge reaching definitions from multiple incoming facts.
        
        Parameters:
        	facts (list[ReachingDefsFact]): Incoming reaching-definition facts.
        
        Returns:
        	ReachingDefsFact: A fact containing the union of all incoming definitions.
        """
        if not facts:
            return ReachingDefsFact()
        merged = ReachingDefsFact()
        for fact in facts:
            merged.defs.update(fact.defs)
        return merged

    def _compute_use_def_chains(self) -> None:
        """Builds use-definition chains by associating each identifier use with its reaching definitions."""
        for node in self.cfg.nodes:
            if self._is_pseudo(node):
                continue
            reaching = self.in_facts.get(node.node_id, ReachingDefsFact())
            uses = _collect_identifiers(node.ast_node, self.source_bytes)
            for var in uses:
                reaching_defs = [d for d in reaching.defs if d.var == var]
                self.use_def_chains[(node.node_id, var)] = reaching_defs

    def get_parameter_influenced_vars(self) -> set[str]:
        """
        Identify variables influenced by function parameters.
        
        Returns:
        	set[str]: Variables that are parameters or are associated with parameter-originating definitions.
        """
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
        """Initialize the liveness analyzer with parameter-influenced variables and an empty dead-assignment list.
        
        Parameters:
        	language (str): The source language.
        	function_node (Node): The tree-sitter function node to analyze.
        	source_bytes (bytes): The source code containing the function.
        	parameter_names (list[str]): Names of the function parameters.
        """
        super().__init__(language, function_node, source_bytes, parameter_names)
        self.param_influenced: set[str] = set(parameter_names)
        self.dead_code: list[tuple[TSCFGNode, str]] = []

    def analyze_liveness(self) -> dict[int, set[str]]:
        """Analyze variable liveness and identify assignments whose values are not subsequently used.
        
        Returns:
        	dict[int, set[str]]: Live variables keyed by control-flow node ID.
        """
        self.analyze(LivenessFact(), forward=False)
        self._detect_dead_code()
        return {
            node_id: fact.live_vars for node_id, fact in self.in_facts.items()
        }

    def transfer(self, node: TSCFGNode, out_fact: LivenessFact) -> LivenessFact:
        """Compute the liveness facts entering a control-flow graph node.
        
        Parameters:
        	node (TSCFGNode): The node whose transfer function is evaluated.
        	out_fact (LivenessFact): Liveness facts after the node.
        
        Returns:
        	LivenessFact: The liveness facts before the node.
        """
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
        """
        Collect variables used by return statements, calls, conditions, and call-valued declarations into the liveness fact.
        
        Parameters:
            ast_node (Node): AST node whose variable uses are analyzed.
            in_fact (LivenessFact): Liveness fact updated with live and parameter-influenced variables.
        """
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
        """
        Merge liveness facts from multiple control-flow paths.
        
        Parameters:
        	facts (list[LivenessFact]): Liveness facts to combine.
        
        Returns:
        	LivenessFact: A fact containing the union of live variables and parameter-influenced live variables.
        """
        if not facts:
            return LivenessFact()
        merged = LivenessFact()
        for fact in facts:
            merged.live_vars.update(fact.live_vars)
            merged.param_influenced_live.update(fact.param_influenced_live)
        return merged

    def _detect_dead_code(self) -> None:
        """Identify assignment nodes whose targets are not live afterward."""
        for node in self.cfg.nodes:
            if self._is_pseudo(node):
                continue
            live_after = self.out_facts.get(node.node_id, LivenessFact())
            for target, _value in _iter_assignments(node.ast_node, self.source_bytes):
                if target not in live_after.live_vars:
                    self.dead_code.append((node, target))

    def get_parameter_live_vars(self) -> set[str]:
        """
        Return variables whose liveness is influenced by function parameters.
        
        Returns:
        	set[str]: A copy of the parameter-influenced variable names.
        """
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
        """
        Initialize the liveness analyzer with a function and its parameters.
        
        Parameters:
            language (str): The source language of the function.
            function_node (Node): The tree-sitter node representing the function.
            source_bytes (bytes): The source code containing the function.
            parameter_names (list[str]): Names of the function parameters.
        """
        super().__init__(language, function_node, source_bytes, parameter_names)
        self.param_influenced: set[str] = set(parameter_names)

    def analyze_available_exprs(self) -> dict[int, set[str]]:
        """
        Run available-expression analysis and collect the expressions available at each CFG node.
        
        Returns:
            dict[int, set[str]]: A mapping from CFG node IDs to their available expressions.
        """
        self.analyze(AvailableExprsFact(), forward=True)
        return {
            node_id: fact.available for node_id, fact in self.out_facts.items()
        }

    def transfer(self, node: TSCFGNode, in_fact: AvailableExprsFact) -> AvailableExprsFact:
        """
        Apply the available-expression transfer for a control-flow graph node.
        
        Parameters:
            node (TSCFGNode): Control-flow graph node being analyzed.
            in_fact (AvailableExprsFact): Available-expression facts entering the node.
        
        Returns:
            AvailableExprsFact: Facts available after processing the node.
        """
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
        """Merge incoming available-expression facts by retaining expressions present on every path."""
        if not facts:
            return AvailableExprsFact()
        merged = facts[0].copy()
        for fact in facts[1:]:
            merged.available &= fact.available
            merged.param_exprs &= fact.param_exprs
        return merged

    def get_parameter_expressions(self) -> set[str]:
        """Collects expressions influenced by function parameters.
        
        Returns:
        	set[str]: All parameter-influenced expressions found in the analysis output facts.
        """
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
    """
    Run reaching-definitions, liveness, and available-expressions analyses for a function.
    
    Returns:
        tuple: The reaching-definitions, liveness, and available-expressions analyzers.
    """
    reaching = TreeSitterReachingDefinitions(language, function_node, source_bytes, parameter_names)
    reaching.analyze_reaching_defs()

    liveness = TreeSitterLivenessAnalyzer(language, function_node, source_bytes, parameter_names)
    liveness.analyze_liveness()

    available = TreeSitterAvailableExpressions(language, function_node, source_bytes, parameter_names)
    available.analyze_available_exprs()

    return reaching, liveness, available
