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

"""Constant propagation for pattern matching with symbolic value tracking."""

import ast
from dataclasses import dataclass
from enum import Enum
from typing import Any

from ..parser.base import BaseParser
from ..parser.python_parser import PythonParser


class ValueKind(Enum):
    """Kind of symbolic value."""
    LITERAL = "literal"
    SYMBOLIC = "symbolic"
    NOT_CONST = "not_const"


@dataclass
class SymbolicValue:
    """Represents a value that may be constant or symbolic."""
    kind: ValueKind
    value: Any = None
    expr: ast.AST | None = None
    dependencies: set[str] | None = None
    
    def is_constant(self) -> bool:
        """Check if this is a concrete constant."""
        return self.kind == ValueKind.LITERAL
    
    def is_symbolic(self) -> bool:
        """Check if this is a symbolic expression."""
        return self.kind == ValueKind.SYMBOLIC
    
    def __repr__(self) -> str:
        """String representation."""
        if self.kind == ValueKind.LITERAL:
            return f"Lit({self.value})"
        elif self.kind == ValueKind.SYMBOLIC:
            try:
                return f"Sym({ast.unparse(self.expr)})"
            except (AttributeError, TypeError, ValueError):
                return "Sym(?)"
        else:
            return "NotCst"


class ConstantPropagationAnalysis:
    """Propagates constant values for matching."""

    def __init__(self, analyzer: BaseParser) -> None:
        """Initialize constant propagator.

        Args:
            analyzer: Language-specific analyzer
        """
        self.analyzer = analyzer
        self.constants: dict[str, Any] = {}
        self.symbolic_values: dict[str, SymbolicValue] = {}

    def analyze(self) -> None:
        """Analyze code and build constant table."""
        ast_root = self.analyzer.get_ast()

        if isinstance(self.analyzer, PythonParser):
            self._analyze_python(ast_root)

    def _analyze_python(self, node: ast.AST) -> None:
        """Analyze Python code for constants and symbolic values.

        Args:
            node: Python AST node
        """
        for n in ast.walk(node):
            if isinstance(n, ast.Assign):
                rhs_value = self._eval_expr(n.value)
                
                for target in n.targets:
                    if isinstance(target, ast.Name):
                        self.symbolic_values[target.id] = rhs_value
                        
                        if rhs_value.is_constant():
                            self.constants[target.id] = rhs_value.value

    def _eval_expr(self, node: ast.AST) -> SymbolicValue:
        """Evaluate an expression to a symbolic value.
        
        Args:
            node: AST node
            
        Returns:
            Symbolic value
        """
        if isinstance(node, ast.Constant):
            return SymbolicValue(kind=ValueKind.LITERAL, value=node.value)
        
        elif isinstance(node, ast.Name):
            if node.id in self.symbolic_values:
                return self.symbolic_values[node.id]
            else:
                return SymbolicValue(
                    kind=ValueKind.SYMBOLIC,
                    expr=node,
                    dependencies={node.id}
                )
        
        elif isinstance(node, ast.BinOp):
            left_val = self._eval_expr(node.left)
            right_val = self._eval_expr(node.right)
            
            if left_val.is_constant() and right_val.is_constant():
                result = self._compute_binop(node.op, left_val.value, right_val.value)
                if result is not None:
                    return SymbolicValue(kind=ValueKind.LITERAL, value=result)
            
            deps = set()
            if left_val.dependencies:
                deps.update(left_val.dependencies)
            if right_val.dependencies:
                deps.update(right_val.dependencies)
            
            return SymbolicValue(
                kind=ValueKind.SYMBOLIC,
                expr=node,
                dependencies=deps
            )
        
        else:
            return SymbolicValue(kind=ValueKind.NOT_CONST)
    
    def _compute_binop(self, op: ast.operator, left: Any, right: Any) -> Any:
        """Compute a binary operation on constants.
        
        Args:
            op: Operator
            left: Left operand value
            right: Right operand value
            
        Returns:
            Result or None
        """
        try:
            if isinstance(op, ast.Add):
                return left + right
            elif isinstance(op, ast.Sub):
                return left - right
            elif isinstance(op, ast.Mult):
                return left * right
            elif isinstance(op, ast.Div):
                return left / right if right != 0 else None
            elif isinstance(op, ast.FloorDiv):
                return left // right if right != 0 else None
            elif isinstance(op, ast.Mod):
                return left % right if right != 0 else None
        except (TypeError, ValueError, ZeroDivisionError):
            return None
        
        return None

    def _eval_binop(self, binop: ast.BinOp) -> Any:
        """Evaluate a binary operation if both operands are constants.

        Args:
            binop: Binary operation node

        Returns:
            Computed value or None
        """
        left_val = self._get_constant_value(binop.left)
        right_val = self._get_constant_value(binop.right)

        if left_val is None or right_val is None:
            return None

        return self._compute_binop(binop.op, left_val, right_val)

    def _get_constant_value(self, node: ast.AST) -> Any:
        """Get constant value of a node.

        Args:
            node: AST node

        Returns:
            Constant value or None
        """
        if isinstance(node, ast.Constant):
            return node.value
        elif isinstance(node, ast.Name):
            return self.constants.get(node.id)
        return None

    def get_constant_value(self, var_name: str) -> Any:
        """Get the constant value of a variable.

        Args:
            var_name: Variable name

        Returns:
            Constant value or None
        """
        return self.constants.get(var_name)

    def resolve_to_constant(self, node: Any) -> Any:
        """Resolve a node to its constant value if possible.

        Args:
            node: AST node

        Returns:
            Constant value or None
        """
        if isinstance(self.analyzer, PythonParser):
            if isinstance(node, ast.Name):
                return self.get_constant_value(node.id)
            elif isinstance(node, ast.Constant):
                return node.value

        return None

    def can_match_constant(self, pattern_value: Any, code_node: Any) -> bool:
        """Check if a pattern constant can match a code node.

        Args:
            pattern_value: Constant value from pattern
            code_node: Code AST node

        Returns:
            True if they can match
        """
        code_value = self.resolve_to_constant(code_node)
        if code_value is not None:
            return pattern_value == code_value

        if isinstance(self.analyzer, PythonParser):
            if isinstance(code_node, ast.BinOp):
                computed = self._eval_binop(code_node)
                if computed is not None:
                    return pattern_value == computed

        return False
