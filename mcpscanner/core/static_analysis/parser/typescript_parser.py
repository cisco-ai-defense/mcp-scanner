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

"""TypeScript/JavaScript source code parser using tree-sitter.

This parser provides TypeScript/JavaScript-specific parsing functionality for the
static analysis engine, following SAST tool conventions.
"""

from pathlib import Path
from typing import Any

import tree_sitter_typescript as ts_typescript
from tree_sitter import Language, Parser, Node

from .base import BaseParser
from ..types import Position, Range


# Initialize TypeScript language
TS_LANGUAGE = Language(ts_typescript.language_typescript())
TSX_LANGUAGE = Language(ts_typescript.language_tsx())


class TypeScriptParser(BaseParser):
    """Parser for TypeScript/JavaScript code using tree-sitter.
    
    Provides comprehensive TypeScript AST parsing and traversal capabilities
    for static security analysis.
    """

    def __init__(self, file_path: Path, source_code: str, is_tsx: bool = False) -> None:
        """Initialize TypeScript parser.

        Args:
            file_path: Path to the TypeScript source file
            source_code: TypeScript source code content
            is_tsx: Whether to parse as TSX (React TypeScript)
        """
        super().__init__(file_path, source_code)
        self.is_tsx = is_tsx
        self._parser = Parser()
        
        # Use TSX language for .tsx files, TypeScript for .ts files
        if is_tsx or str(file_path).endswith('.tsx'):
            self._parser.language = TSX_LANGUAGE
        else:
            self._parser.language = TS_LANGUAGE
        
        self._source_bytes = source_code.encode('utf-8')

    def parse(self) -> Any:
        """Parse TypeScript source code into AST.

        Returns:
            tree-sitter Tree object

        Raises:
            SyntaxError: If source code has syntax errors
        """
        tree = self._parser.parse(self._source_bytes)
        
        # Check for parse errors
        if tree.root_node.has_error:
            # Find the first error node for better error reporting
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

        Includes variable declarations, assignment expressions, and augmented assignments.

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
            'variable_declaration',
            'lexical_declaration',
            'assignment_expression',
            'augmented_assignment_expression',
        }
        
        for n in self.walk(node):
            if n.type in assignment_types:
                assignments.append(n)
        
        return assignments

    def get_function_defs(self, node: Node | None = None) -> list[Node]:
        """Get all function definitions in the AST.

        Includes function declarations, arrow functions, and method definitions.

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
            'function_expression',
            'arrow_function',
            'method_definition',
            'generator_function_declaration',
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
        import_types = {
            'import_statement',
            'import_require_clause',
            'export_statement',  # export { x } from 'y'
        }
        
        for n in self.walk(node):
            if n.type in import_types:
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
        
        # Get the function being called (first child before arguments)
        func_node = node.child_by_field_name('function')
        if func_node is None and node.children:
            func_node = node.children[0]
        
        if func_node is None:
            return ''
        
        return self._extract_identifier_chain(func_node)

    def _extract_identifier_chain(self, node: Node) -> str:
        """Extract identifier chain from a node (e.g., 'a.b.c').

        Args:
            node: AST node

        Returns:
            Identifier chain as string
        """
        if node.type == 'identifier':
            return self.get_node_text(node)
        
        if node.type == 'member_expression':
            obj = node.child_by_field_name('object')
            prop = node.child_by_field_name('property')
            
            if obj and prop:
                obj_name = self._extract_identifier_chain(obj)
                prop_name = self.get_node_text(prop)
                return f"{obj_name}.{prop_name}"
        
        if node.type == 'call_expression':
            func = node.child_by_field_name('function')
            if func:
                return self._extract_identifier_chain(func)
        
        # For other node types, return the text
        return self.get_node_text(node)

    def get_docstring(self, node: Node) -> str | None:
        """Extract JSDoc comment from a function definition.

        Args:
            node: AST node (function_declaration, arrow_function, etc.)

        Returns:
            JSDoc comment text if present, None otherwise
        """
        func_types = {
            'function_declaration',
            'function_expression', 
            'arrow_function',
            'method_definition',
        }
        
        if node.type not in func_types:
            return None
        
        # Look for preceding comment node
        prev_sibling = node.prev_sibling
        while prev_sibling:
            if prev_sibling.type == 'comment':
                comment_text = self.get_node_text(prev_sibling)
                # Check if it's a JSDoc comment
                if comment_text.startswith('/**'):
                    # Clean up the JSDoc comment
                    return self._clean_jsdoc(comment_text)
            elif prev_sibling.type not in {'comment', '\n', ' '}:
                break
            prev_sibling = prev_sibling.prev_sibling
        
        return None

    def _clean_jsdoc(self, comment: str) -> str:
        """Clean up JSDoc comment text.

        Args:
            comment: Raw JSDoc comment

        Returns:
            Cleaned comment text
        """
        lines = comment.split('\n')
        cleaned_lines = []
        
        for line in lines:
            # Remove leading/trailing whitespace
            line = line.strip()
            # Remove comment markers
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
        for n in self.walk(node):
            if n.type == 'class_declaration':
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
        string_types = {'string', 'template_string', 'string_fragment'}
        
        for n in self.walk(node):
            if n.type in string_types:
                text = self.get_node_text(n)
                # Remove quotes
                if text.startswith('"') or text.startswith("'"):
                    text = text[1:-1]
                elif text.startswith('`'):
                    text = text[1:-1]
                if text and text not in strings:
                    strings.append(text)
        
        return strings

    def get_decorators(self, node: Node) -> list[Node]:
        """Get decorators for a class or method.

        Args:
            node: Class or method node

        Returns:
            List of decorator nodes
        """
        decorators: list[Node] = []
        
        # Look for decorator nodes as previous siblings or children
        prev = node.prev_sibling
        while prev:
            if prev.type == 'decorator':
                decorators.insert(0, prev)
            elif prev.type not in {'comment', '\n', ' '}:
                break
            prev = prev.prev_sibling
        
        return decorators

    def get_function_parameters(self, node: Node) -> list[dict[str, Any]]:
        """Get parameters from a function definition.

        Args:
            node: Function definition node

        Returns:
            List of parameter info dicts with name and optional type
        """
        params: list[dict[str, Any]] = []
        
        # Find formal_parameters node
        params_node = node.child_by_field_name('parameters')
        if params_node is None:
            for child in node.children:
                if child.type == 'formal_parameters':
                    params_node = child
                    break
        
        if params_node is None:
            return params
        
        for child in params_node.children:
            if child.type in {'required_parameter', 'optional_parameter', 'rest_parameter'}:
                param_info: dict[str, Any] = {}
                
                # Get parameter name
                pattern = child.child_by_field_name('pattern')
                if pattern:
                    param_info['name'] = self.get_node_text(pattern)
                else:
                    # Try to find identifier directly
                    for subchild in child.children:
                        if subchild.type == 'identifier':
                            param_info['name'] = self.get_node_text(subchild)
                            break
                
                # Get type annotation if present
                type_ann = child.child_by_field_name('type')
                if type_ann:
                    param_info['type'] = self.get_node_text(type_ann)
                
                if 'name' in param_info:
                    params.append(param_info)
            
            elif child.type == 'identifier':
                # Simple parameter without type
                params.append({'name': self.get_node_text(child)})
        
        return params

    def get_return_type(self, node: Node) -> str | None:
        """Get return type annotation from a function.

        Args:
            node: Function definition node

        Returns:
            Return type string or None
        """
        return_type = node.child_by_field_name('return_type')
        if return_type:
            return self.get_node_text(return_type)
        return None

    def get_function_name(self, node: Node) -> str:
        """Get the name of a function definition.

        Args:
            node: Function definition node

        Returns:
            Function name or empty string
        """
        name_node = node.child_by_field_name('name')
        if name_node:
            return self.get_node_text(name_node)
        
        # For arrow functions assigned to variables, look at parent
        parent = node.parent
        if parent and parent.type == 'variable_declarator':
            name_node = parent.child_by_field_name('name')
            if name_node:
                return self.get_node_text(name_node)
        
        return ''
