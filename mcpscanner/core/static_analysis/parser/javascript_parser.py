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

"""JavaScript parser using tree-sitter."""

from pathlib import Path
from typing import Any, List

try:
    from tree_sitter import Language, Parser, Node
    import tree_sitter_javascript
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False
    Node = Any  # Type hint fallback

from .base import BaseParser, Range


class JavaScriptParser(BaseParser):
    """Parser for JavaScript using tree-sitter."""
    
    def __init__(self, file_path: Path, source_code: str):
        """Initialize JavaScript parser.
        
        Args:
            file_path: Path to source file
            source_code: JavaScript source code
            
        Raises:
            ImportError: If tree-sitter is not available
        """
        if not TREE_SITTER_AVAILABLE:
            raise ImportError(
                "tree-sitter and tree-sitter-javascript are required for JavaScript parsing. "
                "Install with: pip install tree-sitter tree-sitter-javascript"
            )
        
        super().__init__(file_path, source_code)
        # tree-sitter 0.21+ wraps language in Language class
        js_language = Language(tree_sitter_javascript.language())
        self.parser = Parser(js_language)
        self._tree = None
    
    def parse(self) -> Node:
        """Parse JavaScript source code.
        
        Returns:
            Tree-sitter syntax tree root node
            
        Raises:
            SyntaxError: If source code has syntax errors
        """
        try:
            tree = self.parser.parse(bytes(self.source_code, 'utf8'))
            self._tree = tree
            
            # Check for syntax errors
            if tree.root_node.has_error:
                raise SyntaxError(f"Failed to parse {self.file_path}: Syntax error in JavaScript")
            
            return tree.root_node
        except Exception as e:
            raise SyntaxError(f"Failed to parse {self.file_path}: {e}") from e
    
    def get_node_range(self, node: Node) -> Range:
        """Get source range for a tree-sitter node.
        
        Args:
            node: Tree-sitter node
            
        Returns:
            Source range
        """
        return Range(
            start_line=node.start_point[0] + 1,  # tree-sitter is 0-indexed
            start_column=node.start_point[1],
            end_line=node.end_point[0] + 1,
            end_column=node.end_point[1]
        )
    
    def get_node_text(self, node: Node) -> str:
        """Get source code text for a node.
        
        Args:
            node: Tree-sitter node
            
        Returns:
            Source code text
        """
        try:
            return node.text.decode('utf8')
        except (AttributeError, UnicodeDecodeError):
            return ""
    
    def walk(self, node: Node | None = None) -> List[Node]:
        """Walk the syntax tree and return all nodes.
        
        Args:
            node: Starting node (uses root if None)
            
        Returns:
            List of all nodes in tree
        """
        if node is None:
            if self._tree is None:
                self.parse()
            node = self._tree.root_node
        
        nodes = [node]
        cursor = node.walk()
        
        visited_children = False
        while True:
            if not visited_children:
                if cursor.goto_first_child():
                    nodes.append(cursor.node)
                    continue
            
            if cursor.goto_next_sibling():
                nodes.append(cursor.node)
                visited_children = False
                continue
            
            if not cursor.goto_parent():
                break
            
            visited_children = True
        
        return nodes
    
    def find_functions(self, node: Node | None = None) -> List[Node]:
        """Find all function definitions.
        
        Args:
            node: Starting node (uses root if None)
            
        Returns:
            List of function nodes
        """
        if node is None:
            if self._tree is None:
                self.parse()
            node = self._tree.root_node
        
        functions = []
        for n in self.walk(node):
            if n.type in [
                'function_declaration',
                'function',
                'arrow_function',
                'method_definition',
                'generator_function_declaration',
            ]:
                functions.append(n)
        
        return functions
    
    def find_mcp_decorated_functions(self) -> List[Node]:
        """Find functions decorated with @mcp.tool() or registered with server.tool().
        
        Returns:
            List of MCP function nodes
        """
        if self._tree is None:
            self.parse()
        
        mcp_functions = []
        
        # Pattern 1: Look for server.registerTool() or server.tool() calls
        for node in self.walk():
            if node.type == 'call_expression':
                callee = node.child_by_field_name('function')
                
                # Pattern 1a: server.registerTool() or server.tool()
                if callee and callee.type == 'member_expression':
                    obj = callee.child_by_field_name('object')
                    prop = callee.child_by_field_name('property')
                    
                    if (obj and prop and 
                        self.get_node_text(obj) == 'server' and
                        self.get_node_text(prop) in ['tool', 'registerTool']):
                        # Found server.registerTool() or server.tool()
                        # Extract the function argument (usually last argument)
                        args = node.child_by_field_name('arguments')
                        if args:
                            # Look for arrow_function or function in arguments
                            for child in args.named_children:
                                if child.type in ['arrow_function', 'function', 'function_expression']:
                                    mcp_functions.append(child)
                
                # Pattern 1b: standalone registerTool() calls
                elif callee and callee.type == 'identifier':
                    func_name = self.get_node_text(callee)
                    if func_name in ['registerTool', 'tool']:
                        # Found registerTool() - extract the function argument
                        args = node.child_by_field_name('arguments')
                        if args:
                            # Look for arrow_function or function in arguments (usually 2nd arg)
                            for child in args.named_children:
                                if child.type in ['arrow_function', 'function', 'function_expression']:
                                    mcp_functions.append(child)
        
        # Pattern 2: Look for @mcp.tool decorators (if using decorators transpiler)
        # This is less common in JS but might appear in some setups
        for node in self.walk():
            if node.type == 'decorator':
                decorator_text = self.get_node_text(node)
                if '@mcp.tool' in decorator_text or '@tool' in decorator_text:
                    # Find the decorated function
                    parent = node.parent
                    if parent:
                        for sibling in parent.children:
                            if sibling.type in ['function_declaration', 'method_definition']:
                                mcp_functions.append(sibling)
        
        return mcp_functions
    
    def get_function_name(self, node: Node) -> str | None:
        """Extract function name from a function node.
        
        Args:
            node: Function node
            
        Returns:
            Function name or None
        """
        if node.type == 'function_declaration':
            name_node = node.child_by_field_name('name')
            if name_node:
                return self.get_node_text(name_node)
        
        elif node.type == 'method_definition':
            name_node = node.child_by_field_name('name')
            if name_node:
                return self.get_node_text(name_node)
        
        elif node.type == 'arrow_function':
            # Arrow functions might not have names, check parent assignment
            parent = node.parent
            if parent and parent.type == 'variable_declarator':
                name_node = parent.child_by_field_name('name')
                if name_node:
                    return self.get_node_text(name_node)
        
        return None
    
    def get_function_parameters(self, node: Node) -> List[str]:
        """Extract parameter names from a function node.
        
        Args:
            node: Function node
            
        Returns:
            List of parameter names
        """
        params = []
        params_node = node.child_by_field_name('parameters')
        
        if params_node:
            for child in params_node.named_children:
                if child.type == 'identifier':
                    params.append(self.get_node_text(child))
                elif child.type == 'required_parameter':
                    # TypeScript typed parameter
                    pattern = child.child_by_field_name('pattern')
                    if pattern and pattern.type == 'identifier':
                        params.append(self.get_node_text(pattern))
                elif child.type == 'object_pattern':
                    # Destructured parameter: { a, b }
                    for prop in child.named_children:
                        if prop.type == 'shorthand_property_identifier_pattern':
                            params.append(self.get_node_text(prop))
                        elif prop.type == 'pair_pattern':
                            # { key: value } pattern
                            value = prop.child_by_field_name('value')
                            if value and value.type == 'identifier':
                                params.append(self.get_node_text(value))
                elif child.type == 'rest_pattern':
                    # Rest parameter (...args)
                    identifier = child.child(1)  # Skip the '...'
                    if identifier:
                        params.append(f"...{self.get_node_text(identifier)}")
        
        return params
    
    def get_function_body(self, node: Node) -> Node | None:
        """Get the body of a function.
        
        Args:
            node: Function node
            
        Returns:
            Body node or None
        """
        return node.child_by_field_name('body')
    
    def is_async_function(self, node: Node) -> bool:
        """Check if a function is async.
        
        Args:
            node: Function node
            
        Returns:
            True if async
        """
        # Check for 'async' keyword in children
        for child in node.children:
            if child.type == 'async' or self.get_node_text(child) == 'async':
                return True
        return False
    
    def extract_jsdoc(self, node: Node) -> str | None:
        """Extract JSDoc comment for a function.
        
        Args:
            node: Function node
            
        Returns:
            JSDoc text or None
        """
        # Look for comment node before the function
        prev_sibling = node.prev_sibling
        while prev_sibling:
            if prev_sibling.type == 'comment':
                comment_text = self.get_node_text(prev_sibling)
                if comment_text.startswith('/**'):
                    return comment_text
            elif prev_sibling.type not in ['comment', 'line_comment']:
                # Stop if we hit a non-comment node
                break
            prev_sibling = prev_sibling.prev_sibling
        
        return None
    
    def find_calls(self, node: Node) -> List[Node]:
        """Find all function calls in a node.
        
        Args:
            node: Node to search
            
        Returns:
            List of call nodes
        """
        calls = []
        for n in self.walk(node):
            if n.type == 'call_expression':
                calls.append(n)
        return calls
    
    def get_call_name(self, node: Node) -> str:
        """Get the name of a function call.
        
        Args:
            node: Call expression node
            
        Returns:
            Function name
        """
        callee = node.child_by_field_name('function')
        if callee:
            if callee.type == 'identifier':
                return self.get_node_text(callee)
            elif callee.type == 'member_expression':
                # obj.method() -> "obj.method"
                return self.get_node_text(callee)
        return "<unknown>"
