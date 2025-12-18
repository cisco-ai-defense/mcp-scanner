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

"""Name resolution analysis with reversed approach for MCP entry points."""

import ast
from typing import Any

from ..parser.base import BaseParser
from ..parser.python_parser import PythonParser


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

    def __init__(self, analyzer: BaseParser, parameter_names: list[str] = None):
        """Initialize name resolver.

        Args:
            analyzer: Language-specific analyzer
            parameter_names: MCP entry point parameter names
        """
        self.analyzer = analyzer
        self.parameter_names = parameter_names or []
        self.global_scope = Scope()
        self.current_scope = self.global_scope
        self.name_to_def: dict[Any, Any] = {}
        self.param_influenced: set[str] = set(parameter_names)

    def resolve(self) -> None:
        """Resolve all names in the AST."""
        ast_root = self.analyzer.get_ast()

        if isinstance(self.analyzer, PythonParser):
            self._resolve_python(ast_root)

    def _resolve_python(self, node: ast.AST) -> None:
        """Resolve names in Python AST.

        Args:
            node: Python AST node
        """
        # Use visitor pattern to properly track scope entry/exit
        self._visit_node(node)

    def _visit_node(self, node: ast.AST) -> None:
        """Visit a node and its children with proper scope tracking.
        
        Args:
            node: AST node to visit
        """
        # Handle scope-creating nodes
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self._visit_function(node)
        elif isinstance(node, ast.ClassDef):
            self._visit_class(node)
        elif isinstance(node, ast.Assign):
            self._define_assignment(node)
            # Visit children
            for child in ast.iter_child_nodes(node):
                self._visit_node(child)
        elif isinstance(node, ast.Import):
            self._define_import(node)
        elif isinstance(node, ast.ImportFrom):
            self._define_import_from(node)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            self._resolve_name(node)
        else:
            # Visit children for other nodes
            for child in ast.iter_child_nodes(node):
                self._visit_node(child)
    
    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        """Visit function with proper scope management.
        
        Args:
            node: Function definition node
        """
        # Define function in current scope
        self.current_scope.define(node.name, node)
        
        # Create and enter new scope for function body
        func_scope = Scope(parent=self.current_scope)
        self.current_scope.children.append(func_scope)
        old_scope = self.current_scope
        self.current_scope = func_scope
        
        # Define parameters in function scope
        for arg in node.args.args:
            is_mcp_param = arg.arg in self.parameter_names
            func_scope.define(arg.arg, arg, is_param=is_mcp_param)
            if is_mcp_param:
                self.param_influenced.add(arg.arg)
        
        # Visit function body
        for child in node.body:
            self._visit_node(child)
        
        # Exit function scope
        self.current_scope = old_scope
    
    def _visit_class(self, node: ast.ClassDef) -> None:
        """Visit class with proper scope management.
        
        Args:
            node: Class definition node
        """
        # Define class in current scope
        self.current_scope.define(node.name, node)
        
        # Create and enter new scope for class body
        class_scope = Scope(parent=self.current_scope)
        self.current_scope.children.append(class_scope)
        old_scope = self.current_scope
        self.current_scope = class_scope
        
        # Visit class body
        for child in node.body:
            self._visit_node(child)
        
        # Exit class scope
        self.current_scope = old_scope

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
