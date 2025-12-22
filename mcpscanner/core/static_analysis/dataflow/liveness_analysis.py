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

"""Liveness analysis with reversed approach for MCP entry points.

REVERSED APPROACH: Track which MCP parameters and parameter-influenced 
variables are live (used later) at each program point.
"""

import ast
from dataclasses import dataclass, field
from typing import Any

from tree_sitter import Node

from ..cfg.builder import CFGNode, DataFlowAnalyzer
from ..parser.base import BaseParser
from ..parser.python_parser import PythonParser
from ..parser.typescript_parser import TypeScriptParser
from ..parser.kotlin_parser import KotlinParser
from ..parser.go_parser import GoParser


@dataclass
class LivenessFact:
    """Liveness dataflow fact - set of live variables."""
    live_vars: set[str] = field(default_factory=set)
    param_influenced_live: set[str] = field(default_factory=set)  # Live vars influenced by MCP params
    
    def copy(self) -> "LivenessFact":
        """Create a copy."""
        return LivenessFact(
            live_vars=self.live_vars.copy(),
            param_influenced_live=self.param_influenced_live.copy()
        )
    
    def __eq__(self, other: object) -> bool:
        """Check equality."""
        if not isinstance(other, LivenessFact):
            return False
        return (self.live_vars == other.live_vars and 
                self.param_influenced_live == other.param_influenced_live)


class LivenessAnalyzer(DataFlowAnalyzer[LivenessFact]):
    """Analyzes which variables are live (will be used later) at each program point.
    
    REVERSED APPROACH: Specifically tracks MCP parameter liveness.
    This is a BACKWARD analysis - facts flow from exit to entry.
    """
    
    def __init__(self, analyzer: BaseParser, parameter_names: list[str] = None):
        """Initialize liveness analyzer.
        
        Args:
            analyzer: Language-specific analyzer
            parameter_names: MCP entry point parameter names
        """
        super().__init__(analyzer)
        self.parameter_names = set(parameter_names or [])
        self.dead_code: list[CFGNode] = []
        self.param_influenced: set[str] = set(parameter_names or [])
    
    def analyze_liveness(self) -> dict[int, set[str]]:
        """Run liveness analysis.
        
        Returns:
            Mapping of node_id -> set of live variables
        """
        self.build_cfg()
        
        # Run BACKWARD dataflow analysis
        initial_fact = LivenessFact()
        self.analyze(initial_fact, forward=False)
        
        # Detect dead code
        self._detect_dead_code()
        
        return {node_id: fact.live_vars for node_id, fact in self.in_facts.items()}
    
    def transfer(self, node: CFGNode, out_fact: LivenessFact) -> LivenessFact:
        """Transfer function for liveness (BACKWARD).
        
        Formula: in = (out - kill) ∪ gen
        - kill = variables defined
        - gen = variables used
        
        Args:
            node: CFG node
            out_fact: Variables live after this node
            
        Returns:
            Variables live before this node
        """
        in_fact = out_fact.copy()
        ast_node = node.ast_node
        
        if isinstance(self.analyzer, PythonParser):
            self._transfer_python(ast_node, in_fact)
        elif isinstance(self.analyzer, TypeScriptParser):
            self._transfer_typescript(ast_node, in_fact)
        elif isinstance(self.analyzer, KotlinParser):
            self._transfer_kotlin(ast_node, in_fact)
        elif isinstance(self.analyzer, GoParser):
            self._transfer_go(ast_node, in_fact)
        
        return in_fact
    
    def _transfer_python(self, ast_node: ast.AST, fact: LivenessFact) -> None:
        """Transfer function for Python nodes.
        
        Args:
            ast_node: Python AST node
            fact: Liveness fact to update (in-place)
        """
        if isinstance(ast_node, ast.Assign):
            # KILL: Remove defined variables
            for target in ast_node.targets:
                if isinstance(target, ast.Name):
                    fact.live_vars.discard(target.id)
                    fact.param_influenced_live.discard(target.id)
            
            # GEN: Add used variables from RHS
            used_vars = self._find_used_vars(ast_node.value)
            fact.live_vars.update(used_vars)
            
            # Track parameter-influenced liveness
            param_used = used_vars & self.param_influenced
            fact.param_influenced_live.update(param_used)
            
            # If RHS uses param-influenced vars, LHS becomes param-influenced
            if param_used:
                for target in ast_node.targets:
                    if isinstance(target, ast.Name):
                        self.param_influenced.add(target.id)
        
        elif isinstance(ast_node, ast.AugAssign):
            if isinstance(ast_node.target, ast.Name):
                var_name = ast_node.target.id
                fact.live_vars.add(var_name)
                if var_name in self.param_influenced:
                    fact.param_influenced_live.add(var_name)
            
            used_vars = self._find_used_vars(ast_node.value)
            fact.live_vars.update(used_vars)
            param_used = used_vars & self.param_influenced
            fact.param_influenced_live.update(param_used)
        
        elif isinstance(ast_node, ast.Return):
            if ast_node.value:
                used_vars = self._find_used_vars(ast_node.value)
                fact.live_vars.update(used_vars)
                param_used = used_vars & self.param_influenced
                fact.param_influenced_live.update(param_used)
        
        elif isinstance(ast_node, ast.If):
            used_vars = self._find_used_vars(ast_node.test)
            fact.live_vars.update(used_vars)
            param_used = used_vars & self.param_influenced
            fact.param_influenced_live.update(param_used)
        
        elif isinstance(ast_node, ast.While):
            used_vars = self._find_used_vars(ast_node.test)
            fact.live_vars.update(used_vars)
            param_used = used_vars & self.param_influenced
            fact.param_influenced_live.update(param_used)
        
        elif isinstance(ast_node, ast.For):
            if isinstance(ast_node.target, ast.Name):
                fact.live_vars.discard(ast_node.target.id)
                fact.param_influenced_live.discard(ast_node.target.id)
            
            used_vars = self._find_used_vars(ast_node.iter)
            fact.live_vars.update(used_vars)
            param_used = used_vars & self.param_influenced
            fact.param_influenced_live.update(param_used)
        
        elif isinstance(ast_node, ast.Expr):
            used_vars = self._find_used_vars(ast_node.value)
            fact.live_vars.update(used_vars)
            param_used = used_vars & self.param_influenced
            fact.param_influenced_live.update(param_used)
    
    def _find_used_vars(self, node: ast.AST) -> set[str]:
        """Find all variables used (read) in an AST node.
        
        Args:
            node: AST node
            
        Returns:
            Set of variable names used
        """
        used = set()
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
                used.add(child.id)
        return used
    
    def merge(self, facts: list[LivenessFact]) -> LivenessFact:
        """Merge multiple liveness facts (UNION).
        
        Args:
            facts: List of facts to merge
            
        Returns:
            Merged fact (union of all live variables)
        """
        if not facts:
            return LivenessFact()
        
        merged = LivenessFact()
        for fact in facts:
            merged.live_vars.update(fact.live_vars)
            merged.param_influenced_live.update(fact.param_influenced_live)
        
        return merged
    
    def _detect_dead_code(self) -> None:
        """Detect dead code - assignments where variable is not live."""
        if not self.cfg:
            return
        
        for node in self.cfg.nodes:
            ast_node = node.ast_node
            
            if isinstance(self.analyzer, PythonParser):
                if isinstance(ast_node, ast.Assign):
                    live_after = self.out_facts.get(node.id, LivenessFact())
                    
                    for target in ast_node.targets:
                        if isinstance(target, ast.Name):
                            if target.id not in live_after.live_vars:
                                self.dead_code.append(node)
    
    def get_parameter_live_vars(self) -> set[str]:
        """Get all parameter-influenced variables that are live.
        
        Returns:
            Set of live parameter-influenced variable names
        """
        return self.param_influenced.copy()
    
    def is_param_live(self, node_id: int, var: str) -> bool:
        """Check if a parameter-influenced variable is live at a node.
        
        Args:
            node_id: CFG node ID
            var: Variable name
            
        Returns:
            True if variable is live and parameter-influenced
        """
        fact = self.in_facts.get(node_id, LivenessFact())
        return var in fact.param_influenced_live

    def _transfer_typescript(self, ast_node: Node, fact: LivenessFact) -> None:
        """Transfer function for TypeScript nodes.

        Args:
            ast_node: tree-sitter Node
            fact: Liveness fact to update (in-place)
        """
        if not isinstance(ast_node, Node):
            return
        
        node_type = ast_node.type
        
        # Variable declarations (const/let/var)
        if node_type in {'variable_declaration', 'lexical_declaration'}:
            for child in ast_node.children:
                if child.type == 'variable_declarator':
                    name_node = child.child_by_field_name('name')
                    value_node = child.child_by_field_name('value')
                    
                    if name_node:
                        var_name = self.analyzer.get_node_text(name_node)
                        # KILL: Remove defined variable
                        fact.live_vars.discard(var_name)
                        fact.param_influenced_live.discard(var_name)
                    
                    if value_node:
                        # GEN: Add used variables from RHS
                        used_vars = self._find_ts_used_vars(value_node)
                        fact.live_vars.update(used_vars)
                        
                        param_used = used_vars & self.param_influenced
                        fact.param_influenced_live.update(param_used)
                        
                        if param_used and name_node:
                            self.param_influenced.add(self.analyzer.get_node_text(name_node))
        
        # Assignment expressions
        elif node_type == 'assignment_expression':
            left = ast_node.child_by_field_name('left')
            right = ast_node.child_by_field_name('right')
            
            if left and left.type == 'identifier':
                var_name = self.analyzer.get_node_text(left)
                fact.live_vars.discard(var_name)
                fact.param_influenced_live.discard(var_name)
            
            if right:
                used_vars = self._find_ts_used_vars(right)
                fact.live_vars.update(used_vars)
                param_used = used_vars & self.param_influenced
                fact.param_influenced_live.update(param_used)
        
        # Return statements
        elif node_type == 'return_statement':
            for child in ast_node.children:
                if child.type not in {'return', ';'}:
                    used_vars = self._find_ts_used_vars(child)
                    fact.live_vars.update(used_vars)
                    param_used = used_vars & self.param_influenced
                    fact.param_influenced_live.update(param_used)
        
        # If statements
        elif node_type == 'if_statement':
            condition = ast_node.child_by_field_name('condition')
            if condition:
                used_vars = self._find_ts_used_vars(condition)
                fact.live_vars.update(used_vars)
                param_used = used_vars & self.param_influenced
                fact.param_influenced_live.update(param_used)
        
        # Expression statements (function calls, etc.)
        elif node_type == 'expression_statement':
            for child in ast_node.children:
                if child.type != ';':
                    used_vars = self._find_ts_used_vars(child)
                    fact.live_vars.update(used_vars)
                    param_used = used_vars & self.param_influenced
                    fact.param_influenced_live.update(param_used)

    def _find_ts_used_vars(self, node: Node) -> set[str]:
        """Find all variables used (read) in a TypeScript node.

        Args:
            node: tree-sitter Node

        Returns:
            Set of variable names used
        """
        used = set()
        for child in self.analyzer.walk(node):
            if child.type == 'identifier':
                # Check if it's being read (not defined)
                parent = child.parent
                if parent and parent.type == 'variable_declarator':
                    name_node = parent.child_by_field_name('name')
                    if name_node == child:
                        continue  # This is a definition, not a use
                used.add(self.analyzer.get_node_text(child))
        return used

    def _transfer_kotlin(self, ast_node: Node, fact: LivenessFact) -> None:
        """Transfer function for Kotlin nodes.

        Args:
            ast_node: tree-sitter Node
            fact: Liveness fact to update (in-place)
        """
        if not isinstance(ast_node, Node):
            return
        
        node_type = ast_node.type
        
        # Property declarations (val/var)
        if node_type == 'property_declaration':
            var_name = ''
            value_node = None
            
            for child in ast_node.children:
                if child.type == 'variable_declaration':
                    for subchild in child.children:
                        if subchild.type in {'identifier', 'simple_identifier'}:
                            var_name = self.analyzer.get_node_text(subchild)
                            break
                elif child.type in {'identifier', 'simple_identifier'} and not var_name:
                    var_name = self.analyzer.get_node_text(child)
                elif child.type not in {'val', 'var', ':', '='}:
                    value_node = child
            
            if var_name:
                # KILL: Remove defined variable
                fact.live_vars.discard(var_name)
                fact.param_influenced_live.discard(var_name)
            
            if value_node:
                # GEN: Add used variables from RHS
                used_vars = self._find_kt_used_vars(value_node)
                fact.live_vars.update(used_vars)
                
                param_used = used_vars & self.param_influenced
                fact.param_influenced_live.update(param_used)
                
                if param_used and var_name:
                    self.param_influenced.add(var_name)
        
        # Assignment expressions
        elif node_type == 'assignment':
            left = None
            right = None
            for i, child in enumerate(ast_node.children):
                if child.type in {'identifier', 'simple_identifier'} and left is None:
                    left = child
                elif child.type == '=':
                    continue
                elif left is not None:
                    right = child
                    break
            
            if left and left.type in {'identifier', 'simple_identifier'}:
                var_name = self.analyzer.get_node_text(left)
                fact.live_vars.discard(var_name)
                fact.param_influenced_live.discard(var_name)
            
            if right:
                used_vars = self._find_kt_used_vars(right)
                fact.live_vars.update(used_vars)
                param_used = used_vars & self.param_influenced
                fact.param_influenced_live.update(param_used)
        
        # Return expressions (jump_expression with return)
        elif node_type == 'jump_expression':
            for child in ast_node.children:
                if child.type not in {'return', 'break', 'continue'}:
                    used_vars = self._find_kt_used_vars(child)
                    fact.live_vars.update(used_vars)
                    param_used = used_vars & self.param_influenced
                    fact.param_influenced_live.update(param_used)
        
        # If expressions
        elif node_type == 'if_expression':
            condition = ast_node.child_by_field_name('condition')
            if condition:
                used_vars = self._find_kt_used_vars(condition)
                fact.live_vars.update(used_vars)
                param_used = used_vars & self.param_influenced
                fact.param_influenced_live.update(param_used)
        
        # Call expressions
        elif node_type == 'call_expression':
            used_vars = self._find_kt_used_vars(ast_node)
            fact.live_vars.update(used_vars)
            param_used = used_vars & self.param_influenced
            fact.param_influenced_live.update(param_used)

    def _find_kt_used_vars(self, node: Node) -> set[str]:
        """Find all variables used (read) in a Kotlin node.

        Args:
            node: tree-sitter Node

        Returns:
            Set of variable names used
        """
        used = set()
        for child in self.analyzer.walk(node):
            if child.type in {'identifier', 'simple_identifier'}:
                # Check if it's being read (not defined)
                parent = child.parent
                if parent and parent.type == 'variable_declaration':
                    continue  # This is a definition, not a use
                if parent and parent.type == 'property_declaration':
                    # Check if this is the name being defined
                    for sibling in parent.children:
                        if sibling.type == 'variable_declaration':
                            for subchild in sibling.children:
                                if subchild == child:
                                    continue
                used.add(self.analyzer.get_node_text(child))
        return used

    def _transfer_go(self, ast_node: Node, fact: LivenessFact) -> None:
        """Transfer function for Go nodes.

        Args:
            ast_node: tree-sitter Node
            fact: Liveness fact to update (in-place)
        """
        if not isinstance(ast_node, Node):
            return
        
        node_type = ast_node.type
        
        # Short var declarations (:=)
        if node_type == 'short_var_declaration':
            left = ast_node.child_by_field_name('left')
            right = ast_node.child_by_field_name('right')
            
            if left:
                for child in left.children:
                    if child.type == 'identifier':
                        var_name = self.analyzer.get_node_text(child)
                        fact.live_vars.discard(var_name)
                        fact.param_influenced_live.discard(var_name)
            
            if right:
                used_vars = self._find_go_used_vars(right)
                fact.live_vars.update(used_vars)
                param_used = used_vars & self.param_influenced
                fact.param_influenced_live.update(param_used)
                
                if param_used and left:
                    for child in left.children:
                        if child.type == 'identifier':
                            self.param_influenced.add(self.analyzer.get_node_text(child))
        
        # Assignment statements
        elif node_type == 'assignment_statement':
            left = ast_node.child_by_field_name('left')
            right = ast_node.child_by_field_name('right')
            
            if left:
                for child in self.analyzer.walk(left):
                    if child.type == 'identifier':
                        var_name = self.analyzer.get_node_text(child)
                        fact.live_vars.discard(var_name)
                        fact.param_influenced_live.discard(var_name)
            
            if right:
                used_vars = self._find_go_used_vars(right)
                fact.live_vars.update(used_vars)
                param_used = used_vars & self.param_influenced
                fact.param_influenced_live.update(param_used)
        
        # Return statements
        elif node_type == 'return_statement':
            for child in ast_node.children:
                if child.type not in {'return', ';'}:
                    used_vars = self._find_go_used_vars(child)
                    fact.live_vars.update(used_vars)
                    param_used = used_vars & self.param_influenced
                    fact.param_influenced_live.update(param_used)
        
        # If statements
        elif node_type == 'if_statement':
            condition = ast_node.child_by_field_name('condition')
            if condition:
                used_vars = self._find_go_used_vars(condition)
                fact.live_vars.update(used_vars)
                param_used = used_vars & self.param_influenced
                fact.param_influenced_live.update(param_used)
        
        # Call expressions
        elif node_type == 'call_expression':
            used_vars = self._find_go_used_vars(ast_node)
            fact.live_vars.update(used_vars)
            param_used = used_vars & self.param_influenced
            fact.param_influenced_live.update(param_used)

    def _find_go_used_vars(self, node: Node) -> set[str]:
        """Find all variables used (read) in a Go node.

        Args:
            node: tree-sitter Node

        Returns:
            Set of variable names used
        """
        used = set()
        for child in self.analyzer.walk(node):
            if child.type == 'identifier':
                parent = child.parent
                if parent and parent.type == 'short_var_declaration':
                    left = parent.child_by_field_name('left')
                    if left and child in self.analyzer.walk(left):
                        continue
                used.add(self.analyzer.get_node_text(child))
        return used
