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

"""Available expressions analysis with reversed approach.

REVERSED APPROACH: Track expressions involving MCP parameters that are 
available (already computed) at each program point.
"""

import ast
from dataclasses import dataclass, field
from typing import Any

from ..cfg.builder import CFGNode, DataFlowAnalyzer
from ..parser.base import BaseParser
from ..parser.python_parser import PythonParser


@dataclass
class AvailableExprsFact:
    """Available expressions dataflow fact."""
    available: set[str] = field(default_factory=set)
    param_exprs: set[str] = field(default_factory=set)  # Expressions involving MCP params
    
    def copy(self) -> "AvailableExprsFact":
        """Create a copy."""
        return AvailableExprsFact(
            available=self.available.copy(),
            param_exprs=self.param_exprs.copy()
        )
    
    def __eq__(self, other: object) -> bool:
        """Check equality."""
        if not isinstance(other, AvailableExprsFact):
            return False
        return self.available == other.available and self.param_exprs == other.param_exprs


class AvailableExpressionsAnalyzer(DataFlowAnalyzer[AvailableExprsFact]):
    """Analyzes which expressions are available at each program point.
    
    REVERSED APPROACH: Specifically tracks expressions involving MCP parameters.
    """
    
    def __init__(self, analyzer: BaseParser, parameter_names: list[str] = None):
        """Initialize available expressions analyzer.
        
        Args:
            analyzer: Language-specific analyzer
            parameter_names: MCP entry point parameter names
        """
        super().__init__(analyzer)
        self.parameter_names = set(parameter_names or [])
        self.param_influenced: set[str] = set(parameter_names or [])
    
    def analyze_available_exprs(self) -> dict[int, set[str]]:
        """Run available expressions analysis.
        
        Returns:
            Mapping of node_id -> set of available expressions
        """
        self.build_cfg()
        
        initial_fact = AvailableExprsFact()
        self.analyze(initial_fact, forward=True)
        
        return {node_id: fact.available for node_id, fact in self.out_facts.items()}
    
    def transfer(self, node: CFGNode, in_fact: AvailableExprsFact) -> AvailableExprsFact:
        """Transfer function for available expressions.
        
        Formula: out = (in - kill) ∪ gen
        
        Args:
            node: CFG node
            in_fact: Available expressions before this node
            
        Returns:
            Available expressions after this node
        """
        out_fact = in_fact.copy()
        ast_node = node.ast_node
        
        if isinstance(self.analyzer, PythonParser):
            self._transfer_python(ast_node, out_fact)
        
        return out_fact
    
    def _transfer_python(self, ast_node: ast.AST, fact: AvailableExprsFact) -> None:
        """Transfer function for Python nodes.
        
        Args:
            ast_node: Python AST node
            fact: Available expressions fact to update
        """
        if isinstance(ast_node, ast.Assign):
            assigned_vars = set()
            for target in ast_node.targets:
                if isinstance(target, ast.Name):
                    assigned_vars.add(target.id)
            
            # KILL: Remove expressions using assigned variables
            fact.available = {
                expr for expr in fact.available
                if not self._expr_uses_vars(expr, assigned_vars)
            }
            fact.param_exprs = {
                expr for expr in fact.param_exprs
                if not self._expr_uses_vars(expr, assigned_vars)
            }
            
            # GEN: Add new expression
            if isinstance(ast_node.value, (ast.BinOp, ast.Call, ast.Attribute)):
                expr_str = self._normalize_expr(ast_node.value)
                if expr_str:
                    fact.available.add(expr_str)
                    
                    # Check if expression involves parameters
                    if self._expr_uses_vars(expr_str, self.param_influenced):
                        fact.param_exprs.add(expr_str)
                        # Mark LHS as parameter-influenced
                        for target in ast_node.targets:
                            if isinstance(target, ast.Name):
                                self.param_influenced.add(target.id)
        
        elif isinstance(ast_node, ast.AugAssign):
            if isinstance(ast_node.target, ast.Name):
                assigned_vars = {ast_node.target.id}
                
                fact.available = {
                    expr for expr in fact.available
                    if not self._expr_uses_vars(expr, assigned_vars)
                }
                fact.param_exprs = {
                    expr for expr in fact.param_exprs
                    if not self._expr_uses_vars(expr, assigned_vars)
                }
        
        elif isinstance(ast_node, ast.Call):
            # Conservative: function calls may modify anything
            fact.available.clear()
            fact.param_exprs.clear()
    
    def _normalize_expr(self, node: ast.AST) -> str:
        """Normalize an expression to a string.
        
        Args:
            node: AST node
            
        Returns:
            Normalized expression string
        """
        try:
            return ast.unparse(node)
        except (AttributeError, TypeError, ValueError):
            return ""
    
    def _expr_uses_vars(self, expr_str: str, vars: set[str]) -> bool:
        """Check if an expression uses any of the given variables.
        
        Args:
            expr_str: Expression string
            vars: Set of variable names
            
        Returns:
            True if expression uses any of the variables
        """
        for var in vars:
            if var in expr_str:
                return True
        return False
    
    def merge(self, facts: list[AvailableExprsFact]) -> AvailableExprsFact:
        """Merge multiple available expressions facts (INTERSECTION).
        
        Args:
            facts: List of facts to merge
            
        Returns:
            Merged fact
        """
        if not facts:
            return AvailableExprsFact()
        
        merged = facts[0].copy()
        
        for fact in facts[1:]:
            merged.available &= fact.available
            merged.param_exprs &= fact.param_exprs
        
        return merged
    
    def get_parameter_expressions(self) -> set[str]:
        """Get all expressions involving MCP parameters.
        
        Returns:
            Set of parameter-influenced expressions
        """
        all_param_exprs = set()
        for fact in self.out_facts.values():
            all_param_exprs.update(fact.param_exprs)
        return all_param_exprs
