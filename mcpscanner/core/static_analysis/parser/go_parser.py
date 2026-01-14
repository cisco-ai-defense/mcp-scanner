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

"""Go source code parser using tree-sitter.

This parser provides Go-specific parsing functionality for the
static analysis engine, following SAST tool conventions.
"""

from pathlib import Path
from typing import Any

import tree_sitter_go as ts_go
from tree_sitter import Language, Parser, Node

from .base import BaseParser
from ..types import Position, Range


# Initialize Go language
GO_LANGUAGE = Language(ts_go.language())


class GoParser(BaseParser):
    """Parser for Go code using tree-sitter.
    
    Provides comprehensive Go AST parsing and traversal capabilities
    for static security analysis.
    """

    def __init__(self, file_path: Path, source_code: str) -> None:
        """Initialize Go parser.

        Args:
            file_path: Path to the Go source file
            source_code: Go source code content
        """
        super().__init__(file_path, source_code)
        self._parser = Parser()
        self._parser.language = GO_LANGUAGE
        self._source_bytes = source_code.encode('utf-8')

    def parse(self) -> Any:
        """Parse Go source code into AST.

        Returns:
            tree-sitter Tree object

        Raises:
            SyntaxError: If source code has syntax errors
        """
        tree = self._parser.parse(self._source_bytes)
        
        # Check for parse errors
        if tree.root_node.has_error:
            error_node = self._find_first_error(tree.root_node)
            if error_node:
                raise SyntaxError(
                    f"Failed to parse {self.file_path}: syntax error at line {error_node.start_point[0] + 1}"
                )
        
        return tree

    def _find_first_error(self, node: Node) -> Node | None:
        """Find the first error node in the tree.

        Args:
            node: Starting node

        Returns:
            First error node or None
        """
        if node.is_error or node.is_missing:
            return node
        
        for child in node.children:
            error = self._find_first_error(child)
            if error:
                return error
        
        return None

    def get_node_range(self, node: Node) -> Range:
        """Get source range for an AST node.

        Args:
            node: tree-sitter Node

        Returns:
            Source range
        """
        start_line, start_col = node.start_point
        end_line, end_col = node.end_point
        
        return Range(
            start=Position(line=start_line + 1, column=start_col, offset=node.start_byte),
            end=Position(line=end_line + 1, column=end_col, offset=node.end_byte),
        )

    def get_node_text(self, node: Node) -> str:
        """Get source text for an AST node.

        Args:
            node: tree-sitter Node

        Returns:
            Source code text
        """
        return self._source_bytes[node.start_byte:node.end_byte].decode('utf-8')

    def walk(self, node: Node | None = None) -> list[Node]:
        """Walk AST and return all nodes.

        Args:
            node: Starting node (None for root)

        Returns:
            List of all nodes
        """
        if node is None:
            tree = self.get_ast()
            node = tree if isinstance(tree, Node) else tree.root_node
        
        nodes = [node]
        for child in node.children:
            nodes.extend(self.walk(child))
        
        return nodes

    def get_function_calls(self, node: Node | None = None) -> list[Node]:
        """Get all function calls in the AST.

        Args:
            node: Starting node (None for root)

        Returns:
            List of call_expression nodes
        """
        if node is None:
            tree = self.get_ast()
            node = tree if isinstance(tree, Node) else tree.root_node
        
        calls: list[Node] = []
        
        for n in self.walk(node):
            if n.type == 'call_expression':
                calls.append(n)
        
        return calls

    def get_assignments(self, node: Node | None = None) -> list[Node]:
        """Get all assignments in the AST.

        Args:
            node: Starting node (None for root)

        Returns:
            List of assignment nodes
        """
        if node is None:
            tree = self.get_ast()
            node = tree if isinstance(tree, Node) else tree.root_node
        
        assignments: list[Node] = []
        assignment_types = {
            'short_var_declaration',
            'var_declaration',
            'assignment_statement',
            'const_declaration',
        }
        
        for n in self.walk(node):
            if n.type in assignment_types:
                assignments.append(n)
        
        return assignments

    def get_function_defs(self, node: Node | None = None) -> list[Node]:
        """Get all function definitions in the AST.

        Args:
            node: Starting node (None for root)

        Returns:
            List of function definition nodes
        """
        if node is None:
            tree = self.get_ast()
            node = tree if isinstance(tree, Node) else tree.root_node
        
        funcs: list[Node] = []
        func_types = {
            'function_declaration',
            'method_declaration',
            'func_literal',
        }
        
        for n in self.walk(node):
            if n.type in func_types:
                funcs.append(n)
        
        return funcs

    def get_imports(self, node: Node | None = None) -> list[Node]:
        """Get all import statements in the AST.

        Args:
            node: Starting node (None for root)

        Returns:
            List of import nodes
        """
        if node is None:
            tree = self.get_ast()
            node = tree if isinstance(tree, Node) else tree.root_node
        
        imports: list[Node] = []
        
        for n in self.walk(node):
            if n.type == 'import_declaration':
                imports.append(n)
        
        return imports

    def get_node_type(self, node: Node) -> str:
        """Get the type name of an AST node.

        Args:
            node: AST node

        Returns:
            Type name as string
        """
        return node.type

    def is_call_to(self, node: Node, func_name: str) -> bool:
        """Check if node is a call to a specific function.

        Args:
            node: AST node
            func_name: Function name to check

        Returns:
            True if node is a call to func_name
        """
        if node.type != 'call_expression':
            return False
        
        call_name = self.get_call_name(node)
        return call_name == func_name or call_name.endswith('.' + func_name)

    def get_call_name(self, node: Node) -> str:
        """Get the name of a function call.

        Args:
            node: call_expression node

        Returns:
            Function name
        """
        if node.type != 'call_expression':
            return ''
        
        # Get the function being called
        func_node = node.child_by_field_name('function')
        if func_node:
            return self._extract_identifier_chain(func_node)
        
        # Fallback: look for first identifier or selector_expression
        for child in node.children:
            if child.type in {'identifier', 'selector_expression'}:
                return self._extract_identifier_chain(child)
        
        return ''

    def _extract_identifier_chain(self, node: Node) -> str:
        """Extract identifier chain from a node (e.g., 'pkg.Func').

        Args:
            node: AST node

        Returns:
            Identifier chain as string
        """
        if node.type == 'identifier':
            return self.get_node_text(node)
        
        if node.type == 'selector_expression':
            operand = node.child_by_field_name('operand')
            field = node.child_by_field_name('field')
            
            if operand and field:
                operand_text = self._extract_identifier_chain(operand)
                field_text = self.get_node_text(field)
                return f"{operand_text}.{field_text}"
        
        if node.type == 'call_expression':
            func_node = node.child_by_field_name('function')
            if func_node:
                return self._extract_identifier_chain(func_node)
        
        return self.get_node_text(node)

    def get_function_name(self, node: Node) -> str:
        """Get the name of a function definition.

        Args:
            node: function_declaration or method_declaration node

        Returns:
            Function name
        """
        if node.type not in {'function_declaration', 'method_declaration', 'func_literal'}:
            return ''
        
        # For func_literal (anonymous functions), return empty
        if node.type == 'func_literal':
            return ''
        
        name_node = node.child_by_field_name('name')
        if name_node:
            return self.get_node_text(name_node)
        
        return ''

    def get_function_parameters(self, node: Node) -> list[dict[str, Any]]:
        """Get parameters of a function definition.

        Args:
            node: function_declaration or method_declaration node

        Returns:
            List of parameter info dicts with 'name' and 'type' keys
        """
        params: list[dict[str, Any]] = []
        
        if node.type not in {'function_declaration', 'method_declaration', 'func_literal'}:
            return params
        
        # Find parameter_list
        param_list = node.child_by_field_name('parameters')
        if not param_list:
            return params
        
        for child in param_list.children:
            if child.type == 'parameter_declaration':
                # Get parameter names and type
                param_type = ''
                param_names = []
                
                for subchild in child.children:
                    if subchild.type == 'identifier':
                        param_names.append(self.get_node_text(subchild))
                    elif subchild.type in {'type_identifier', 'pointer_type', 'slice_type', 
                                          'array_type', 'map_type', 'qualified_type'}:
                        param_type = self.get_node_text(subchild)
                
                for name in param_names:
                    params.append({'name': name, 'type': param_type})
        
        return params

    def get_class_defs(self, node: Node | None = None) -> list[Node]:
        """Get all struct/interface definitions in the AST.

        Args:
            node: Starting node (None for root)

        Returns:
            List of type definition nodes
        """
        if node is None:
            tree = self.get_ast()
            node = tree if isinstance(tree, Node) else tree.root_node
        
        types: list[Node] = []
        
        for n in self.walk(node):
            if n.type == 'type_declaration':
                types.append(n)
        
        return types

    def get_class_name(self, node: Node) -> str:
        """Get the name of a type definition.

        Args:
            node: type_declaration node

        Returns:
            Type name
        """
        if node.type != 'type_declaration':
            return ''
        
        # Find type_spec inside type_declaration
        for child in node.children:
            if child.type == 'type_spec':
                name_node = child.child_by_field_name('name')
                if name_node:
                    return self.get_node_text(name_node)
        
        return ''

    def get_decorators(self, node: Node) -> list[Node]:
        """Get decorators/annotations for a node.

        Go doesn't have decorators, but we can look for comment annotations.

        Args:
            node: AST node

        Returns:
            List of comment nodes that might be annotations
        """
        # Go uses comments for annotations (like //go:generate)
        decorators: list[Node] = []
        
        # Look for preceding comments
        if node.prev_sibling and node.prev_sibling.type == 'comment':
            decorators.append(node.prev_sibling)
        
        return decorators

    def get_annotations(self, node: Node) -> list[Node]:
        """Alias for get_decorators for Go.

        Args:
            node: AST node

        Returns:
            List of annotation nodes
        """
        return self.get_decorators(node)

    def get_method_receiver(self, node: Node) -> str | None:
        """Get the receiver type for a method declaration.

        Args:
            node: method_declaration node

        Returns:
            Receiver type name or None
        """
        if node.type != 'method_declaration':
            return None
        
        receiver = node.child_by_field_name('receiver')
        if receiver:
            # Find the type in the receiver
            for child in self.walk(receiver):
                if child.type in {'type_identifier', 'pointer_type'}:
                    return self.get_node_text(child)
        
        return None
