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

from tree_sitter import Node

from ..parser.base import BaseParser
from ..parser.python_parser import PythonParser
from ..parser.typescript_parser import TypeScriptParser
from ..parser.kotlin_parser import KotlinParser
from ..parser.go_parser import GoParser


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
        elif isinstance(self.analyzer, TypeScriptParser):
            root = ast_root.root_node if hasattr(ast_root, 'root_node') else ast_root
            self._analyze_typescript(root)
        elif isinstance(self.analyzer, KotlinParser):
            root = ast_root.root_node if hasattr(ast_root, 'root_node') else ast_root
            self._analyze_kotlin(root)
        elif isinstance(self.analyzer, GoParser):
            root = ast_root.root_node if hasattr(ast_root, 'root_node') else ast_root
            self._analyze_go(root)

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

    def _analyze_typescript(self, node: Node) -> None:
        """Analyze TypeScript code for constants and symbolic values.

        Args:
            node: tree-sitter Node
        """
        for n in self.analyzer.walk(node):
            # Handle variable declarations (const/let/var)
            if n.type in {'variable_declaration', 'lexical_declaration'}:
                for child in n.children:
                    if child.type == 'variable_declarator':
                        name_node = child.child_by_field_name('name')
                        value_node = child.child_by_field_name('value')
                        
                        if name_node and value_node:
                            var_name = self.analyzer.get_node_text(name_node)
                            rhs_value = self._eval_ts_expr(value_node)
                            
                            self.symbolic_values[var_name] = rhs_value
                            if rhs_value.is_constant():
                                self.constants[var_name] = rhs_value.value

    def _eval_ts_expr(self, node: Node) -> SymbolicValue:
        """Evaluate a TypeScript expression to a symbolic value.

        Args:
            node: tree-sitter Node

        Returns:
            Symbolic value
        """
        if not isinstance(node, Node):
            return SymbolicValue(kind=ValueKind.NOT_CONST)
        
        node_type = node.type
        
        # String literals
        if node_type == 'string':
            text = self.analyzer.get_node_text(node)
            # Remove quotes
            value = text[1:-1] if len(text) >= 2 else text
            return SymbolicValue(kind=ValueKind.LITERAL, value=value)
        
        # Number literals
        if node_type == 'number':
            text = self.analyzer.get_node_text(node)
            try:
                if '.' in text:
                    return SymbolicValue(kind=ValueKind.LITERAL, value=float(text))
                else:
                    return SymbolicValue(kind=ValueKind.LITERAL, value=int(text))
            except ValueError:
                return SymbolicValue(kind=ValueKind.NOT_CONST)
        
        # Boolean literals
        if node_type in {'true', 'false'}:
            return SymbolicValue(kind=ValueKind.LITERAL, value=node_type == 'true')
        
        # Identifiers - check if we know the value
        if node_type == 'identifier':
            name = self.analyzer.get_node_text(node)
            if name in self.symbolic_values:
                return self.symbolic_values[name]
            return SymbolicValue(kind=ValueKind.SYMBOLIC, dependencies={name})
        
        # Binary expressions
        if node_type == 'binary_expression':
            left = node.child_by_field_name('left')
            right = node.child_by_field_name('right')
            operator = node.child_by_field_name('operator')
            
            if left and right and operator:
                left_val = self._eval_ts_expr(left)
                right_val = self._eval_ts_expr(right)
                op_text = self.analyzer.get_node_text(operator)
                
                if left_val.is_constant() and right_val.is_constant():
                    result = self._compute_ts_binop(op_text, left_val.value, right_val.value)
                    if result is not None:
                        return SymbolicValue(kind=ValueKind.LITERAL, value=result)
                
                deps = set()
                if left_val.dependencies:
                    deps.update(left_val.dependencies)
                if right_val.dependencies:
                    deps.update(right_val.dependencies)
                return SymbolicValue(kind=ValueKind.SYMBOLIC, dependencies=deps)
        
        # Template strings - check if all parts are constant
        if node_type == 'template_string':
            parts = []
            all_const = True
            for child in node.children:
                if child.type == 'string_fragment':
                    parts.append(self.analyzer.get_node_text(child))
                elif child.type == 'template_substitution':
                    for subchild in child.children:
                        if subchild.type not in {'${', '}'}:
                            sub_val = self._eval_ts_expr(subchild)
                            if sub_val.is_constant():
                                parts.append(str(sub_val.value))
                            else:
                                all_const = False
            
            if all_const:
                return SymbolicValue(kind=ValueKind.LITERAL, value=''.join(parts))
        
        return SymbolicValue(kind=ValueKind.NOT_CONST)

    def _compute_ts_binop(self, op: str, left: Any, right: Any) -> Any:
        """Compute a TypeScript binary operation on constants.

        Args:
            op: Operator string
            left: Left operand value
            right: Right operand value

        Returns:
            Result or None
        """
        try:
            if op == '+':
                return left + right
            elif op == '-':
                return left - right
            elif op == '*':
                return left * right
            elif op == '/':
                return left / right if right != 0 else None
            elif op == '%':
                return left % right if right != 0 else None
        except (TypeError, ValueError, ZeroDivisionError):
            return None
        return None

    def _analyze_kotlin(self, node: Node) -> None:
        """Analyze Kotlin code for constants and symbolic values.

        Args:
            node: tree-sitter Node
        """
        for n in self.analyzer.walk(node):
            # Handle property declarations (val/var)
            if n.type == 'property_declaration':
                var_name = ''
                value_node = None
                
                for child in n.children:
                    if child.type == 'variable_declaration':
                        for subchild in child.children:
                            if subchild.type in {'identifier', 'simple_identifier'}:
                                var_name = self.analyzer.get_node_text(subchild)
                                break
                    elif child.type in {'identifier', 'simple_identifier'} and not var_name:
                        var_name = self.analyzer.get_node_text(child)
                    elif child.type in {'string_literal', 'integer_literal', 'boolean_literal',
                                       'real_literal', 'call_expression', 'navigation_expression'}:
                        value_node = child
                
                if var_name and value_node:
                    rhs_value = self._eval_kt_expr(value_node)
                    self.symbolic_values[var_name] = rhs_value
                    if rhs_value.is_constant():
                        self.constants[var_name] = rhs_value.value

    def _eval_kt_expr(self, node: Node) -> SymbolicValue:
        """Evaluate a Kotlin expression to a symbolic value.

        Args:
            node: tree-sitter Node

        Returns:
            Symbolic value
        """
        if not isinstance(node, Node):
            return SymbolicValue(kind=ValueKind.NOT_CONST)
        
        node_type = node.type
        
        # String literals
        if node_type == 'string_literal':
            text = self.analyzer.get_node_text(node)
            # Remove quotes
            if text.startswith('"') and text.endswith('"'):
                value = text[1:-1]
            else:
                value = text
            return SymbolicValue(kind=ValueKind.LITERAL, value=value)
        
        # Integer literals
        if node_type == 'integer_literal':
            text = self.analyzer.get_node_text(node)
            try:
                return SymbolicValue(kind=ValueKind.LITERAL, value=int(text))
            except ValueError:
                return SymbolicValue(kind=ValueKind.NOT_CONST)
        
        # Real/float literals
        if node_type == 'real_literal':
            text = self.analyzer.get_node_text(node)
            try:
                return SymbolicValue(kind=ValueKind.LITERAL, value=float(text.rstrip('fF')))
            except ValueError:
                return SymbolicValue(kind=ValueKind.NOT_CONST)
        
        # Boolean literals
        if node_type == 'boolean_literal':
            text = self.analyzer.get_node_text(node)
            return SymbolicValue(kind=ValueKind.LITERAL, value=text == 'true')
        
        # Identifiers - check if we know the value
        if node_type in {'identifier', 'simple_identifier'}:
            name = self.analyzer.get_node_text(node)
            if name in self.symbolic_values:
                return self.symbolic_values[name]
            return SymbolicValue(kind=ValueKind.SYMBOLIC, dependencies={name})
        
        # Additive/multiplicative expressions
        if node_type in {'additive_expression', 'multiplicative_expression'}:
            children = list(node.children)
            if len(children) >= 3:
                left_val = self._eval_kt_expr(children[0])
                op_text = self.analyzer.get_node_text(children[1])
                right_val = self._eval_kt_expr(children[2])
                
                if left_val.is_constant() and right_val.is_constant():
                    result = self._compute_ts_binop(op_text, left_val.value, right_val.value)
                    if result is not None:
                        return SymbolicValue(kind=ValueKind.LITERAL, value=result)
        
        return SymbolicValue(kind=ValueKind.NOT_CONST)

    def _analyze_go(self, node: Node) -> None:
        """Analyze Go code for constants and symbolic values.

        Args:
            node: tree-sitter Node
        """
        for n in self.analyzer.walk(node):
            # Handle const declarations
            if n.type == 'const_declaration':
                for child in n.children:
                    if child.type == 'const_spec':
                        name_node = None
                        value_node = None
                        for subchild in child.children:
                            if subchild.type == 'identifier' and name_node is None:
                                name_node = subchild
                            elif subchild.type == 'expression_list':
                                # Get first expression from expression_list
                                for expr in subchild.children:
                                    if expr.type != ',':
                                        value_node = expr
                                        break
                            elif subchild.type in {'interpreted_string_literal', 'raw_string_literal',
                                                  'int_literal', 'float_literal', 'true', 'false'}:
                                value_node = subchild
                        
                        if name_node and value_node:
                            var_name = self.analyzer.get_node_text(name_node)
                            rhs_value = self._eval_go_expr(value_node)
                            self.symbolic_values[var_name] = rhs_value
                            if rhs_value.is_constant():
                                self.constants[var_name] = rhs_value.value
            
            # Handle short var declarations (:=)
            elif n.type == 'short_var_declaration':
                left = n.child_by_field_name('left')
                right = n.child_by_field_name('right')
                
                if left and right:
                    names = [c for c in left.children if c.type == 'identifier']
                    values = [c for c in right.children if c.type != ',']
                    
                    for i, name_node in enumerate(names):
                        var_name = self.analyzer.get_node_text(name_node)
                        if i < len(values):
                            rhs_value = self._eval_go_expr(values[i])
                            self.symbolic_values[var_name] = rhs_value
                            if rhs_value.is_constant():
                                self.constants[var_name] = rhs_value.value

    def _eval_go_expr(self, node: Node) -> SymbolicValue:
        """Evaluate a Go expression to a symbolic value.

        Args:
            node: tree-sitter Node

        Returns:
            Symbolic value
        """
        if not isinstance(node, Node):
            return SymbolicValue(kind=ValueKind.NOT_CONST)
        
        node_type = node.type
        
        # String literals
        if node_type in {'interpreted_string_literal', 'raw_string_literal'}:
            text = self.analyzer.get_node_text(node)
            if text.startswith('"') and text.endswith('"'):
                value = text[1:-1]
            elif text.startswith('`') and text.endswith('`'):
                value = text[1:-1]
            else:
                value = text
            return SymbolicValue(kind=ValueKind.LITERAL, value=value)
        
        # Integer literals
        if node_type == 'int_literal':
            text = self.analyzer.get_node_text(node)
            try:
                return SymbolicValue(kind=ValueKind.LITERAL, value=int(text, 0))
            except ValueError:
                return SymbolicValue(kind=ValueKind.NOT_CONST)
        
        # Float literals
        if node_type == 'float_literal':
            text = self.analyzer.get_node_text(node)
            try:
                return SymbolicValue(kind=ValueKind.LITERAL, value=float(text))
            except ValueError:
                return SymbolicValue(kind=ValueKind.NOT_CONST)
        
        # Boolean literals
        if node_type in {'true', 'false'}:
            return SymbolicValue(kind=ValueKind.LITERAL, value=node_type == 'true')
        
        # Identifiers
        if node_type == 'identifier':
            name = self.analyzer.get_node_text(node)
            if name in self.symbolic_values:
                return self.symbolic_values[name]
            return SymbolicValue(kind=ValueKind.SYMBOLIC, dependencies={name})
        
        # Binary expressions
        if node_type == 'binary_expression':
            left = node.child_by_field_name('left')
            right = node.child_by_field_name('right')
            operator = node.child_by_field_name('operator')
            
            if left and right and operator:
                left_val = self._eval_go_expr(left)
                right_val = self._eval_go_expr(right)
                op_text = self.analyzer.get_node_text(operator)
                
                if left_val.is_constant() and right_val.is_constant():
                    result = self._compute_ts_binop(op_text, left_val.value, right_val.value)
                    if result is not None:
                        return SymbolicValue(kind=ValueKind.LITERAL, value=result)
        
        return SymbolicValue(kind=ValueKind.NOT_CONST)
