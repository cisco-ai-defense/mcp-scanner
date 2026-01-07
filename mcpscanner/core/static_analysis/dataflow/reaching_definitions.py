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

"""Reaching definitions analysis with reversed approach for MCP entry points."""

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


@dataclass(frozen=True)
class Definition:
    """Represents a variable definition."""
    var: str
    node_id: int
    is_parameter: bool = False  # Track if this is an MCP entry point parameter
    
    def __hash__(self) -> int:
        """Hash for set membership."""
        return hash((self.var, self.node_id, self.is_parameter))


@dataclass
class ReachingDefsFact:
    """Reaching definitions dataflow fact."""
    defs: set[Definition] = field(default_factory=set)
    
    def copy(self) -> "ReachingDefsFact":
        """Create a copy."""
        return ReachingDefsFact(defs=self.defs.copy())
    
    def __eq__(self, other: object) -> bool:
        """Check equality."""
        if not isinstance(other, ReachingDefsFact):
            return False
        return self.defs == other.defs


class ReachingDefinitionsAnalysis(DataFlowAnalyzer[ReachingDefsFact]):
    """Analyzes which definitions reach which program points.
    
    REVERSED APPROACH: Tracks how MCP entry point parameters flow through definitions.
    """
    
    def __init__(self, analyzer: BaseParser, parameter_names: list[str] = None):
        """Initialize reaching definitions analyzer.
        
        Args:
            analyzer: Language-specific analyzer
            parameter_names: MCP entry point parameter names (for reversed approach)
        """
        super().__init__(analyzer)
        self.parameter_names = parameter_names or []
        self.use_def_chains: dict[tuple[int, str], list[Definition]] = {}
    
    def analyze_reaching_defs(self) -> dict[tuple[int, str], list[Definition]]:
        """Run reaching definitions analysis.
        
        Returns:
            Use-def chains: (node_id, var) -> list of reaching definitions
        """
        self.build_cfg()
        
        # Initialize with parameter definitions (REVERSED APPROACH)
        initial_fact = ReachingDefsFact()
        for param_name in self.parameter_names:
            # Parameters are initial definitions (sources)
            param_def = Definition(var=param_name, node_id=-1, is_parameter=True)
            initial_fact.defs.add(param_def)
        
        self.analyze(initial_fact)
        self._compute_use_def_chains()
        
        return self.use_def_chains
    
    def transfer(self, node: CFGNode, in_fact: ReachingDefsFact) -> ReachingDefsFact:
        """Transfer function for reaching definitions.
        
        Args:
            node: CFG node
            in_fact: Input reaching definitions
            
        Returns:
            Output reaching definitions
        """
        out_fact = in_fact.copy()
        ast_node = node.ast_node
        
        if isinstance(self.analyzer, PythonParser):
            self._transfer_python(ast_node, node, out_fact)
        elif isinstance(self.analyzer, TypeScriptParser):
            self._transfer_typescript(ast_node, node, out_fact)
        elif isinstance(self.analyzer, KotlinParser):
            self._transfer_kotlin(ast_node, node, out_fact)
        elif isinstance(self.analyzer, GoParser):
            self._transfer_go(ast_node, node, out_fact)
        
        return out_fact
    
    def _transfer_python(self, ast_node: ast.AST, cfg_node: CFGNode, fact: ReachingDefsFact) -> None:
        """Transfer function for Python nodes.
        
        Args:
            ast_node: Python AST node
            cfg_node: CFG node
            fact: Reaching definitions fact to update
        """
        if isinstance(ast_node, ast.Assign):
            for target in ast_node.targets:
                if isinstance(target, ast.Name):
                    var_name = target.id
                    
                    # GEN: Check if RHS uses any parameters BEFORE kill
                    # This preserves taint chain for self-referential updates (x = x + 1)
                    uses_param = self._expr_uses_parameters(ast_node.value, fact)
                    
                    # KILL: Remove all previous definitions of this variable
                    fact.defs = {d for d in fact.defs if d.var != var_name}
                    
                    # Add new definition with preserved parameter flag
                    new_def = Definition(var=var_name, node_id=cfg_node.id, is_parameter=uses_param)
                    fact.defs.add(new_def)
        
        elif isinstance(ast_node, ast.AugAssign):
            if isinstance(ast_node.target, ast.Name):
                var_name = ast_node.target.id
                
                # Check BEFORE kill (augmented assignments always reference the target)
                uses_param = self._expr_uses_parameters(ast_node.value, fact)
                # Also check if target itself is parameter-derived
                target_defs = [d for d in fact.defs if d.var == var_name]
                if any(d.is_parameter for d in target_defs):
                    uses_param = True
                
                fact.defs = {d for d in fact.defs if d.var != var_name}
                
                new_def = Definition(var=var_name, node_id=cfg_node.id, is_parameter=uses_param)
                fact.defs.add(new_def)
        
        elif isinstance(ast_node, ast.For):
            if isinstance(ast_node.target, ast.Name):
                var_name = ast_node.target.id
                
                # Check BEFORE kill
                uses_param = self._expr_uses_parameters(ast_node.iter, fact)
                
                fact.defs = {d for d in fact.defs if d.var != var_name}
                
                new_def = Definition(var=var_name, node_id=cfg_node.id, is_parameter=uses_param)
                fact.defs.add(new_def)
    
    def _expr_uses_parameters(self, expr: ast.AST, fact: ReachingDefsFact) -> bool:
        """Check if expression uses any MCP entry point parameters (transitively).
        
        Args:
            expr: Expression node
            fact: Current reaching definitions
            
        Returns:
            True if expression uses parameters
        """
        for node in ast.walk(expr):
            if isinstance(node, ast.Name):
                # Check if this variable has parameter definitions reaching it
                reaching_defs = [d for d in fact.defs if d.var == node.id]
                if any(d.is_parameter for d in reaching_defs):
                    return True
        return False
    
    def merge(self, facts: list[ReachingDefsFact]) -> ReachingDefsFact:
        """Merge multiple reaching definitions facts.
        
        Args:
            facts: List of facts to merge
            
        Returns:
            Merged fact (union of all definitions)
        """
        if not facts:
            return ReachingDefsFact()
        
        merged = ReachingDefsFact()
        for fact in facts:
            merged.defs.update(fact.defs)
        
        return merged
    
    def _compute_use_def_chains(self) -> None:
        """Compute use-def chains from reaching definitions."""
        if not self.cfg:
            return
        
        for node in self.cfg.nodes:
            ast_node = node.ast_node
            
            reaching = self.in_facts.get(node.id, ReachingDefsFact())
            uses = self._find_uses(ast_node)
            
            for var in uses:
                reaching_defs = [d for d in reaching.defs if d.var == var]
                self.use_def_chains[(node.id, var)] = reaching_defs
    
    def _find_uses(self, node: ast.AST) -> set[str]:
        """Find all variable uses in an AST node.
        
        Args:
            node: AST node
            
        Returns:
            Set of variable names used
        """
        uses = set()
        
        if isinstance(self.analyzer, PythonParser):
            for child in ast.walk(node):
                if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
                    uses.add(child.id)
        elif isinstance(self.analyzer, (TypeScriptParser, KotlinParser, GoParser)):
            uses = self._find_ts_kt_uses(node)
        
        return uses
    
    def get_reaching_defs(self, node_id: int, var: str) -> list[Definition]:
        """Get reaching definitions for a variable at a node.
        
        Args:
            node_id: CFG node ID
            var: Variable name
            
        Returns:
            List of reaching definitions
        """
        return self.use_def_chains.get((node_id, var), [])
    
    def get_parameter_influenced_vars(self) -> set[str]:
        """Get all variables influenced by MCP entry point parameters.
        
        Returns:
            Set of variable names that depend on parameters
        """
        influenced = set()
        
        for (node_id, var), defs in self.use_def_chains.items():
            if any(d.is_parameter for d in defs):
                influenced.add(var)
        
        return influenced

    def _transfer_typescript(self, ast_node: Node, cfg_node: CFGNode, fact: ReachingDefsFact) -> None:
        """Transfer function for TypeScript nodes.

        Args:
            ast_node: tree-sitter Node
            cfg_node: CFG node
            fact: Reaching definitions fact to update
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
                        
                        # Check if RHS uses parameters BEFORE kill
                        uses_param = False
                        if value_node:
                            uses_param = self._ts_expr_uses_parameters(value_node, fact)
                        
                        # KILL: Remove previous definitions
                        fact.defs = {d for d in fact.defs if d.var != var_name}
                        
                        # GEN: Add new definition
                        new_def = Definition(var=var_name, node_id=cfg_node.id, is_parameter=uses_param)
                        fact.defs.add(new_def)
        
        # Assignment expressions
        elif node_type == 'assignment_expression':
            left = ast_node.child_by_field_name('left')
            right = ast_node.child_by_field_name('right')
            
            if left and left.type == 'identifier':
                var_name = self.analyzer.get_node_text(left)
                
                uses_param = False
                if right:
                    uses_param = self._ts_expr_uses_parameters(right, fact)
                
                fact.defs = {d for d in fact.defs if d.var != var_name}
                new_def = Definition(var=var_name, node_id=cfg_node.id, is_parameter=uses_param)
                fact.defs.add(new_def)

    def _transfer_kotlin(self, ast_node: Node, cfg_node: CFGNode, fact: ReachingDefsFact) -> None:
        """Transfer function for Kotlin nodes.

        Args:
            ast_node: tree-sitter Node
            cfg_node: CFG node
            fact: Reaching definitions fact to update
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
                uses_param = False
                if value_node:
                    uses_param = self._kt_expr_uses_parameters(value_node, fact)
                
                fact.defs = {d for d in fact.defs if d.var != var_name}
                new_def = Definition(var=var_name, node_id=cfg_node.id, is_parameter=uses_param)
                fact.defs.add(new_def)
        
        # Assignment expressions
        elif node_type == 'assignment':
            left = None
            right = None
            for child in ast_node.children:
                if child.type in {'identifier', 'simple_identifier'} and left is None:
                    left = child
                elif child.type == '=':
                    continue
                elif left is not None:
                    right = child
                    break
            
            if left:
                var_name = self.analyzer.get_node_text(left)
                uses_param = False
                if right:
                    uses_param = self._kt_expr_uses_parameters(right, fact)
                
                fact.defs = {d for d in fact.defs if d.var != var_name}
                new_def = Definition(var=var_name, node_id=cfg_node.id, is_parameter=uses_param)
                fact.defs.add(new_def)

    def _ts_expr_uses_parameters(self, node: Node, fact: ReachingDefsFact) -> bool:
        """Check if TypeScript expression uses any parameters.

        Args:
            node: tree-sitter Node
            fact: Current reaching definitions

        Returns:
            True if expression uses parameters
        """
        for child in self.analyzer.walk(node):
            if child.type == 'identifier':
                name = self.analyzer.get_node_text(child)
                reaching_defs = [d for d in fact.defs if d.var == name]
                if any(d.is_parameter for d in reaching_defs):
                    return True
        return False

    def _kt_expr_uses_parameters(self, node: Node, fact: ReachingDefsFact) -> bool:
        """Check if Kotlin expression uses any parameters.

        Args:
            node: tree-sitter Node
            fact: Current reaching definitions

        Returns:
            True if expression uses parameters
        """
        for child in self.analyzer.walk(node):
            if child.type in {'identifier', 'simple_identifier'}:
                name = self.analyzer.get_node_text(child)
                reaching_defs = [d for d in fact.defs if d.var == name]
                if any(d.is_parameter for d in reaching_defs):
                    return True
        return False

    def _find_ts_kt_uses(self, node: Any) -> set[str]:
        """Find all variable uses in a TypeScript/Kotlin node.

        Args:
            node: tree-sitter Node

        Returns:
            Set of variable names used
        """
        uses = set()
        if not isinstance(node, Node):
            return uses
        
        for child in self.analyzer.walk(node):
            if child.type in {'identifier', 'simple_identifier'}:
                # Check if it's being read (not defined)
                parent = child.parent
                if parent and parent.type == 'variable_declarator':
                    name_node = parent.child_by_field_name('name')
                    if name_node == child:
                        continue
                if parent and parent.type == 'variable_declaration':
                    continue
                uses.add(self.analyzer.get_node_text(child))
        return uses

    def _transfer_go(self, ast_node: Node, cfg_node: CFGNode, fact: ReachingDefsFact) -> None:
        """Transfer function for Go nodes.

        Args:
            ast_node: tree-sitter Node
            cfg_node: CFG node
            fact: Reaching definitions fact to update
        """
        if not isinstance(ast_node, Node):
            return
        
        node_type = ast_node.type
        
        # Short var declarations (:=)
        if node_type == 'short_var_declaration':
            left = ast_node.child_by_field_name('left')
            right = ast_node.child_by_field_name('right')
            
            if left:
                names = [c for c in left.children if c.type == 'identifier']
                
                uses_param = False
                if right:
                    uses_param = self._go_expr_uses_parameters(right, fact)
                
                for name_node in names:
                    var_name = self.analyzer.get_node_text(name_node)
                    fact.defs = {d for d in fact.defs if d.var != var_name}
                    new_def = Definition(var=var_name, node_id=cfg_node.id, is_parameter=uses_param)
                    fact.defs.add(new_def)
        
        # Assignment statements
        elif node_type == 'assignment_statement':
            left = ast_node.child_by_field_name('left')
            right = ast_node.child_by_field_name('right')
            
            if left:
                uses_param = False
                if right:
                    uses_param = self._go_expr_uses_parameters(right, fact)
                
                for child in self.analyzer.walk(left):
                    if child.type == 'identifier':
                        var_name = self.analyzer.get_node_text(child)
                        fact.defs = {d for d in fact.defs if d.var != var_name}
                        new_def = Definition(var=var_name, node_id=cfg_node.id, is_parameter=uses_param)
                        fact.defs.add(new_def)

    def _go_expr_uses_parameters(self, node: Node, fact: ReachingDefsFact) -> bool:
        """Check if Go expression uses any parameters.

        Args:
            node: tree-sitter Node
            fact: Current reaching definitions

        Returns:
            True if expression uses parameters
        """
        for child in self.analyzer.walk(node):
            if child.type == 'identifier':
                name = self.analyzer.get_node_text(child)
                reaching_defs = [d for d in fact.defs if d.var == name]
                if any(d.is_parameter for d in reaching_defs):
                    return True
        return False
