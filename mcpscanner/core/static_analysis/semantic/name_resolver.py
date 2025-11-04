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

"""Name resolution analysis with reversed approach for MCP entry points.

MULTI-LANGUAGE SUPPORT: Now supports all 10 languages through unified AST.
"""

import ast
from typing import Any, Optional

from ..parser.base import BaseParser
from ..parser.python_parser import PythonParser
from ..unified_ast import UnifiedASTNode, NodeType
from ..language_detector import Language


class Scope:
    """Represents a lexical scope."""

    def __init__(self, parent: "Scope | None" = None) -> None:
        """Initialize scope.

        Args:
            parent: Parent scope
        """
        self.parent = parent
        self.symbols: dict[str, Any] = {}
        self.children: list[Scope] = []
        self.is_parameter: dict[str, bool] = {}  # Track if symbol is MCP parameter

    def define(self, name: str, node: Any, is_param: bool = False) -> None:
        """Define a symbol in this scope.

        Args:
            name: Symbol name
            node: AST node defining the symbol
            is_param: Whether this is an MCP entry point parameter
        """
        self.symbols[name] = node
        self.is_parameter[name] = is_param

    def lookup(self, name: str) -> Any | None:
        """Look up a symbol in this scope or parent scopes.

        Args:
            name: Symbol name

        Returns:
            AST node or None if not found
        """
        if name in self.symbols:
            return self.symbols[name]
        elif self.parent:
            return self.parent.lookup(name)
        return None

    def is_param_influenced(self, name: str) -> bool:
        """Check if a symbol is influenced by MCP parameters.

        Args:
            name: Symbol name

        Returns:
            True if influenced by parameters
        """
        if name in self.is_parameter:
            return self.is_parameter[name]
        elif self.parent:
            return self.parent.is_param_influenced(name)
        return False


class NameResolver:
    """Resolves names to their definitions.
    
    REVERSED APPROACH: Tracks which names are influenced by MCP entry point parameters.
    """

    def __init__(self, analyzer: BaseParser, parameter_names: list[str] = None, language: Optional[Language] = None):
        """Initialize name resolver.

        Args:
            analyzer: Language-specific analyzer
            parameter_names: MCP entry point parameter names
            language: Programming language (for unified analysis)
        """
        self.analyzer = analyzer
        self.parameter_names = parameter_names or []
        self.language = language
        self.global_scope = Scope()
        self.current_scope = self.global_scope
        self.name_to_def: dict[Any, Any] = {}
        self.param_influenced: set[str] = set(parameter_names)

    def resolve(self) -> None:
        """Resolve all names in the AST."""
        ast_root = self.analyzer.get_ast()

        if isinstance(self.analyzer, PythonParser):
            self._resolve_python(ast_root)

    def resolve_unified(self, unified_nodes: list[UnifiedASTNode]) -> None:
        """Resolve names in unified AST nodes (supports all languages).

        Args:
            unified_nodes: List of UnifiedASTNode (typically functions)
        """
        for node in unified_nodes:
            self._resolve_unified_node(node)

    def _resolve_unified_node(self, node: UnifiedASTNode) -> None:
        """Resolve names in a unified AST node.

        Args:
            node: Unified AST node
        """
        # Define function parameters in scope
        if node.type in [NodeType.FUNCTION, NodeType.ASYNC_FUNCTION]:
            for param_name in node.parameters:
                is_param = param_name in self.parameter_names
                self.current_scope.define(param_name, node, is_param)
                if is_param:
                    self.param_influenced.add(param_name)

        # Track assignments and variable dependencies
        if node.metadata:
            # Process assignments
            if 'assignments' in node.metadata:
                for assignment in node.metadata['assignments']:
                    target = assignment.get('target')
                    if target:
                        self.current_scope.define(target, node, False)
                        
                        # Check if assignment uses parameter-influenced variables
                        if self._unified_assignment_uses_params(assignment, node):
                            self.param_influenced.add(target)

            # Process variable dependencies
            if 'variable_dependencies' in node.metadata:
                deps = node.metadata['variable_dependencies']
                for var_name, dep_vars in deps.items():
                    # If any dependency is parameter-influenced, mark this var as influenced
                    if any(dep in self.param_influenced for dep in dep_vars):
                        self.param_influenced.add(var_name)

        # Recursively resolve children
        for child in node.children:
            self._resolve_unified_node(child)

    def _unified_assignment_uses_params(self, assignment: dict, context_node: UnifiedASTNode) -> bool:
        """Check if assignment uses parameter-influenced variables.

        Args:
            assignment: Assignment metadata
            context_node: Context node

        Returns:
            True if uses parameters
        """
        # Check variable dependencies
        if context_node.metadata and 'variable_dependencies' in context_node.metadata:
            deps = context_node.metadata['variable_dependencies']
            target = assignment.get('target')
            if target in deps:
                dep_vars = deps[target]
                return any(var in self.param_influenced for var in dep_vars)
        
        return False

    def _resolve_python(self, node: ast.AST) -> None:
        """Resolve names in Python AST.

        Args:
            node: Python AST node
        """
        # First pass: build symbol table
        for n in ast.walk(node):
            if isinstance(n, ast.FunctionDef):
                self._define_function(n)
            elif isinstance(n, ast.ClassDef):
                self._define_class(n)
            elif isinstance(n, ast.Assign):
                self._define_assignment(n)
            elif isinstance(n, ast.Import):
                self._define_import(n)
            elif isinstance(n, ast.ImportFrom):
                self._define_import_from(n)

        # Second pass: resolve name references and track parameter influence
        for n in ast.walk(node):
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load):
                self._resolve_name(n)

    def _define_function(self, node: ast.FunctionDef) -> None:
        """Define a function in current scope.

        Args:
            node: Function definition node
        """
        self.current_scope.define(node.name, node)

        # Create new scope for function body
        func_scope = Scope(parent=self.current_scope)
        self.current_scope.children.append(func_scope)

        # Define parameters (mark as MCP parameters if applicable)
        for arg in node.args.args:
            is_mcp_param = arg.arg in self.parameter_names
            func_scope.define(arg.arg, arg, is_param=is_mcp_param)
            if is_mcp_param:
                self.param_influenced.add(arg.arg)

    def _define_class(self, node: ast.ClassDef) -> None:
        """Define a class in current scope.

        Args:
            node: Class definition node
        """
        self.current_scope.define(node.name, node)

    def _define_assignment(self, node: ast.Assign) -> None:
        """Define variables from assignment.

        Args:
            node: Assignment node
        """
        # Check if RHS uses parameter-influenced variables
        rhs_uses_params = self._expr_uses_params(node.value)
        
        for target in node.targets:
            if isinstance(target, ast.Name):
                self.current_scope.define(target.id, node, is_param=rhs_uses_params)
                if rhs_uses_params:
                    self.param_influenced.add(target.id)
            elif isinstance(target, ast.Tuple):
                for elt in target.elts:
                    if isinstance(elt, ast.Name):
                        self.current_scope.define(elt.id, node, is_param=rhs_uses_params)
                        if rhs_uses_params:
                            self.param_influenced.add(elt.id)

    def _expr_uses_params(self, expr: ast.AST) -> bool:
        """Check if expression uses parameter-influenced variables.

        Args:
            expr: Expression node

        Returns:
            True if uses parameters
        """
        for node in ast.walk(expr):
            if isinstance(node, ast.Name):
                if node.id in self.param_influenced:
                    return True
                if self.current_scope.is_param_influenced(node.id):
                    return True
        return False

    def _define_import(self, node: ast.Import) -> None:
        """Define imported names.

        Args:
            node: Import node
        """
        for alias in node.names:
            name = alias.asname if alias.asname else alias.name
            self.current_scope.define(name, node)

    def _define_import_from(self, node: ast.ImportFrom) -> None:
        """Define names from 'from ... import' statement.

        Args:
            node: ImportFrom node
        """
        for alias in node.names:
            name = alias.asname if alias.asname else alias.name
            self.current_scope.define(name, node)

    def _resolve_name(self, node: ast.Name) -> None:
        """Resolve a name reference to its definition.

        Args:
            node: Name node
        """
        definition = self.current_scope.lookup(node.id)
        if definition:
            self.name_to_def[node] = definition

    def get_definition(self, node: Any) -> Any | None:
        """Get the definition for a name usage.

        Args:
            node: Name usage node

        Returns:
            Definition node or None
        """
        return self.name_to_def.get(node)

    def get_parameter_influenced_vars(self) -> set[str]:
        """Get all variables influenced by MCP entry point parameters.

        Returns:
            Set of variable names
        """
        return self.param_influenced.copy()

    def is_influenced_by_parameters(self, var_name: str) -> bool:
        """Check if a variable is influenced by MCP parameters.

        Args:
            var_name: Variable name

        Returns:
            True if influenced
        """
        return var_name in self.param_influenced
