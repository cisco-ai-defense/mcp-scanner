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

"""Kotlin source code parser using tree-sitter.

This parser provides Kotlin-specific parsing functionality for the
static analysis engine, following SAST tool conventions.
"""

from pathlib import Path
from typing import Any

import tree_sitter_kotlin as ts_kotlin
from tree_sitter import Language, Parser, Node

from .base import BaseParser
from ..types import Position, Range


# Initialize Kotlin language
KOTLIN_LANGUAGE = Language(ts_kotlin.language())


class KotlinParser(BaseParser):
    """Parser for Kotlin code using tree-sitter.
    
    Provides comprehensive Kotlin AST parsing and traversal capabilities
    for static security analysis.
    """

    def __init__(self, file_path: Path, source_code: str) -> None:
        """Initialize Kotlin parser.

        Args:
            file_path: Path to the Kotlin source file
            source_code: Kotlin source code content
        """
        super().__init__(file_path, source_code)
        self._parser = Parser()
        self._parser.language = KOTLIN_LANGUAGE
        self._source_bytes = source_code.encode('utf-8')

    def parse(self) -> Any:
        """Parse Kotlin source code into AST.

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
        call_types = {'call_expression', 'infix_expression'}
        
        for n in self.walk(node):
            if n.type in call_types:
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
            'property_declaration',
            'variable_declaration',
            'assignment',
            'augmented_assignment',
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
            'anonymous_function',
            'lambda_literal',
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
            # tree-sitter-kotlin uses 'import' as the node type
            if n.type == 'import' and n.parent and n.parent.type == 'source_file':
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
        for child in node.children:
            if child.type == 'identifier':
                return self.get_node_text(child)
            elif child.type in {'navigation_expression', 'simple_identifier', 'call_expression'}:
                return self._extract_identifier_chain(child)
        
        return ''

    def _extract_identifier_chain(self, node: Node) -> str:
        """Extract identifier chain from a node (e.g., 'a.b.c').

        Args:
            node: AST node

        Returns:
            Identifier chain as string
        """
        if node.type in {'simple_identifier', 'identifier'}:
            return self.get_node_text(node)
        
        if node.type == 'navigation_expression':
            parts = []
            for child in node.children:
                if child.type in {'simple_identifier', 'identifier'}:
                    parts.append(self.get_node_text(child))
                elif child.type == 'navigation_expression':
                    parts.append(self._extract_identifier_chain(child))
                elif child.type == 'call_expression':
                    parts.append(self._extract_identifier_chain(child))
            return '.'.join(parts)
        
        if node.type == 'call_expression':
            for child in node.children:
                if child.type in {'navigation_expression', 'simple_identifier', 'identifier'}:
                    return self._extract_identifier_chain(child)
        
        return self.get_node_text(node)

    def get_docstring(self, node: Node) -> str | None:
        """Extract KDoc comment from a function definition.

        Args:
            node: AST node (function_declaration, etc.)

        Returns:
            KDoc comment text if present, None otherwise
        """
        if node.type not in {'function_declaration', 'class_declaration'}:
            return None
        
        # Look for preceding multiline_comment node (KDoc)
        prev_sibling = node.prev_sibling
        while prev_sibling:
            if prev_sibling.type == 'multiline_comment':
                comment_text = self.get_node_text(prev_sibling)
                if comment_text.startswith('/**'):
                    return self._clean_kdoc(comment_text)
            elif prev_sibling.type not in {'comment', '\n', ' '}:
                break
            prev_sibling = prev_sibling.prev_sibling
        
        return None

    def _clean_kdoc(self, comment: str) -> str:
        """Clean up KDoc comment text.

        Args:
            comment: Raw KDoc comment

        Returns:
            Cleaned comment text
        """
        lines = comment.split('\n')
        cleaned_lines = []
        
        for line in lines:
            line = line.strip()
            if line.startswith('/**'):
                line = line[3:]
            elif line.startswith('*/'):
                continue
            elif line.startswith('*'):
                line = line[1:]
            
            line = line.strip()
            if line:
                cleaned_lines.append(line)
        
        return '\n'.join(cleaned_lines)

    def get_class_defs(self, node: Node | None = None) -> list[Node]:
        """Get all class definitions in the AST.

        Args:
            node: Starting node (None for root)

        Returns:
            List of class_declaration nodes
        """
        if node is None:
            tree = self.get_ast()
            node = tree if isinstance(tree, Node) else tree.root_node
        
        classes: list[Node] = []
        class_types = {'class_declaration', 'object_declaration'}
        
        for n in self.walk(node):
            if n.type in class_types:
                classes.append(n)
        
        return classes

    def get_string_literals(self, node: Node | None = None) -> list[str]:
        """Get all string literals in the AST.

        Args:
            node: Starting node (None for root)

        Returns:
            List of string literal values
        """
        if node is None:
            tree = self.get_ast()
            node = tree if isinstance(tree, Node) else tree.root_node
        
        strings: list[str] = []
        string_types = {'string_literal', 'line_string_literal', 'multi_line_string_literal'}
        
        for n in self.walk(node):
            if n.type in string_types:
                text = self.get_node_text(n)
                # Remove quotes
                if text.startswith('"""'):
                    text = text[3:-3]
                elif text.startswith('"'):
                    text = text[1:-1]
                if text and text not in strings:
                    strings.append(text)
        
        return strings

    def get_annotations(self, node: Node) -> list[Node]:
        """Get annotations for a class or function.

        Args:
            node: Class or function node

        Returns:
            List of annotation nodes
        """
        annotations: list[Node] = []
        
        # Look for modifiers containing annotations
        for child in node.children:
            if child.type == 'modifiers':
                for mod_child in child.children:
                    if mod_child.type == 'annotation':
                        annotations.append(mod_child)
        
        return annotations

    def get_function_parameters(self, node: Node) -> list[dict[str, Any]]:
        """Get parameters from a function definition.

        Args:
            node: Function definition node

        Returns:
            List of parameter info dicts with name and optional type
        """
        params: list[dict[str, Any]] = []
        
        # Find function_value_parameters node
        for child in node.children:
            if child.type == 'function_value_parameters':
                for param_child in child.children:
                    if param_child.type == 'parameter':
                        param_info: dict[str, Any] = {}
                        
                        for subchild in param_child.children:
                            if subchild.type in {'simple_identifier', 'identifier'}:
                                param_info['name'] = self.get_node_text(subchild)
                            elif subchild.type in {'user_type', 'nullable_type'}:
                                param_info['type'] = self.get_node_text(subchild)
                        
                        if 'name' in param_info:
                            params.append(param_info)
        
        return params

    def get_return_type(self, node: Node) -> str | None:
        """Get return type annotation from a function.

        Args:
            node: Function definition node

        Returns:
            Return type string or None
        """
        # Look for type after colon in function declaration
        found_colon = False
        for child in node.children:
            if child.type == ':':
                found_colon = True
            elif found_colon and child.type in {'user_type', 'nullable_type', 'function_type'}:
                return self.get_node_text(child)
        
        return None

    def get_function_name(self, node: Node) -> str:
        """Get the name of a function definition.

        Args:
            node: Function definition node

        Returns:
            Function name or empty string
        """
        for child in node.children:
            if child.type in {'simple_identifier', 'identifier'}:
                return self.get_node_text(child)
        
        return ''

    def get_class_name(self, node: Node) -> str:
        """Get the name of a class definition.

        Args:
            node: Class definition node

        Returns:
            Class name or empty string
        """
        for child in node.children:
            if child.type in {'type_identifier', 'identifier'}:
                return self.get_node_text(child)
        
        return ''
