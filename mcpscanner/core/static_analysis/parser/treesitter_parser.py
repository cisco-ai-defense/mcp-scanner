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

"""Tree-sitter based parser for multiple languages.

This parser provides language-agnostic parsing functionality using tree-sitter,
following the same BaseParser interface as PythonParser.

Supported languages: TypeScript, JavaScript, Go, Java, Kotlin, C#, Ruby, Rust, PHP
"""

from pathlib import Path
from typing import Any, Dict, List, Optional

from tree_sitter import Language, Parser, Node, Tree

from .base import BaseParser
from ..types import Position, Range


# Language module cache
_LANGUAGE_CACHE: Dict[str, Language] = {}


def _get_language(lang_name: str) -> Optional[Language]:
    """Get tree-sitter Language for a language name."""
    if lang_name in _LANGUAGE_CACHE:
        return _LANGUAGE_CACHE[lang_name]
    
    try:
        if lang_name == "javascript":
            import tree_sitter_javascript as mod
            lang = Language(mod.language())
        elif lang_name == "typescript":
            import tree_sitter_typescript as mod
            lang = Language(mod.language_typescript())
        elif lang_name == "tsx":
            import tree_sitter_typescript as mod
            lang = Language(mod.language_tsx())
        elif lang_name == "go":
            import tree_sitter_go as mod
            lang = Language(mod.language())
        elif lang_name == "java":
            import tree_sitter_java as mod
            lang = Language(mod.language())
        elif lang_name == "kotlin":
            import tree_sitter_kotlin as mod
            lang = Language(mod.language())
        elif lang_name == "c_sharp":
            import tree_sitter_c_sharp as mod
            lang = Language(mod.language())
        elif lang_name == "ruby":
            import tree_sitter_ruby as mod
            lang = Language(mod.language())
        elif lang_name == "rust":
            import tree_sitter_rust as mod
            lang = Language(mod.language())
        elif lang_name == "php":
            import tree_sitter_php as mod
            lang = Language(mod.language_php())
        else:
            return None
        
        _LANGUAGE_CACHE[lang_name] = lang
        return lang
    except ImportError:
        return None


# File extension to language mapping
EXTENSION_TO_LANGUAGE = {
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "tsx",
    ".go": "go",
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".cs": "c_sharp",
    ".rb": "ruby",
    ".rs": "rust",
    ".php": "php",
}


class TreeSitterParser(BaseParser):
    """Parser for multiple languages using tree-sitter.
    
    Provides the same interface as PythonParser but works with
    tree-sitter for TypeScript, JavaScript, Go, Java, Kotlin, C#, Ruby, Rust, PHP.
    """
    
    # Function node types per language
    FUNCTION_TYPES = {
        "javascript": {"function_declaration", "function_expression", "arrow_function", "method_definition"},
        "typescript": {"function_declaration", "function_expression", "arrow_function", "method_definition"},
        "tsx": {"function_declaration", "function_expression", "arrow_function", "method_definition"},
        "go": {"function_declaration", "method_declaration"},
        "java": {"method_declaration", "constructor_declaration"},
        "kotlin": {"function_declaration", "secondary_constructor"},
        "c_sharp": {"method_declaration", "constructor_declaration", "local_function_statement"},
        "ruby": {"method", "singleton_method"},
        "rust": {"function_item"},
        "php": {"function_definition", "method_declaration"},
    }
    
    # Call expression types per language
    CALL_TYPES = {
        "javascript": {"call_expression", "new_expression"},
        "typescript": {"call_expression", "new_expression"},
        "tsx": {"call_expression", "new_expression"},
        "go": {"call_expression"},
        "java": {"method_invocation", "object_creation_expression"},
        "kotlin": {"call_expression"},
        "c_sharp": {"invocation_expression", "object_creation_expression"},
        "ruby": {"call", "method_call"},
        "rust": {"call_expression", "macro_invocation"},
        "php": {"function_call_expression", "member_call_expression", "scoped_call_expression"},
    }
    
    # Import node types per language
    IMPORT_TYPES = {
        "javascript": {"import_statement"},
        "typescript": {"import_statement"},
        "tsx": {"import_statement"},
        "go": {"import_declaration"},
        "java": {"import_declaration"},
        "kotlin": {"import_header"},
        "c_sharp": {"using_directive"},
        "ruby": {"call"},  # require/require_relative
        "rust": {"use_declaration"},
        "php": {"namespace_use_declaration"},
    }
    
    # Assignment types per language
    ASSIGNMENT_TYPES = {
        "javascript": {"variable_declarator", "assignment_expression", "augmented_assignment_expression"},
        "typescript": {"variable_declarator", "assignment_expression", "augmented_assignment_expression"},
        "tsx": {"variable_declarator", "assignment_expression", "augmented_assignment_expression"},
        "go": {"short_var_declaration", "assignment_statement", "var_spec"},
        "java": {"variable_declarator", "assignment_expression"},
        "kotlin": {"property_declaration", "variable_declaration"},
        "c_sharp": {"variable_declarator", "assignment_expression"},
        "ruby": {"assignment"},
        "rust": {"let_declaration", "assignment_expression"},
        "php": {"assignment_expression", "simple_variable"},
    }
    
    def __init__(self, file_path: Path, source_code: str, language: str = None) -> None:
        """Initialize tree-sitter parser.
        
        Args:
            file_path: Path to the source file
            source_code: Source code content
            language: Language name (auto-detected from extension if not provided)
        """
        super().__init__(file_path, source_code)
        self.source_bytes = source_code.encode("utf-8")
        
        # Determine language
        if language:
            self.language = language
        else:
            ext = file_path.suffix.lower()
            self.language = EXTENSION_TO_LANGUAGE.get(ext)
        
        self._tree: Optional[Tree] = None
        self._parser: Optional[Parser] = None
    
    def _get_parser(self) -> Optional[Parser]:
        """Get or create parser for the language."""
        if self._parser:
            return self._parser
        
        lang = _get_language(self.language)
        if lang:
            self._parser = Parser(lang)
        return self._parser
    
    def parse(self) -> Tree:
        """Parse source code into tree-sitter AST.
        
        Returns:
            Tree-sitter Tree
            
        Raises:
            ValueError: If language is not supported or parsing fails
        """
        parser = self._get_parser()
        if not parser:
            raise ValueError(f"Unsupported language: {self.language}")
        
        self._tree = parser.parse(self.source_bytes)
        self._ast = self._tree
        return self._tree
    
    def get_node_range(self, node: Node) -> Range:
        """Get source range for a tree-sitter node.
        
        Args:
            node: Tree-sitter Node
            
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
        """Get source text for a tree-sitter node.
        
        Args:
            node: Tree-sitter Node
            
        Returns:
            Source code text
        """
        return self.source_bytes[node.start_byte:node.end_byte].decode("utf-8")
    
    def walk(self, node: Node = None) -> List[Node]:
        """Walk AST and return all nodes.
        
        Args:
            node: Starting node (None for root)
            
        Returns:
            List of all nodes
        """
        if node is None:
            if self._tree is None:
                self.parse()
            node = self._tree.root_node
        
        nodes = []
        
        def visit(n: Node):
            nodes.append(n)
            for child in n.children:
                visit(child)
        
        visit(node)
        return nodes
    
    def get_function_calls(self, node: Node = None) -> List[Node]:
        """Get all function calls in the AST.
        
        Args:
            node: Starting node (None for root)
            
        Returns:
            List of call nodes
        """
        call_types = self.CALL_TYPES.get(self.language, set())
        return [n for n in self.walk(node) if n.type in call_types]
    
    def get_assignments(self, node: Node = None) -> List[Node]:
        """Get all assignments in the AST.
        
        Args:
            node: Starting node (None for root)
            
        Returns:
            List of assignment nodes
        """
        assign_types = self.ASSIGNMENT_TYPES.get(self.language, set())
        return [n for n in self.walk(node) if n.type in assign_types]
    
    def get_function_defs(self, node: Node = None) -> List[Node]:
        """Get all function definitions in the AST.
        
        Args:
            node: Starting node (None for root)
            
        Returns:
            List of function definition nodes
        """
        func_types = self.FUNCTION_TYPES.get(self.language, set())
        return [n for n in self.walk(node) if n.type in func_types]
    
    def get_imports(self, node: Node = None) -> List[Node]:
        """Get all import statements in the AST.
        
        Args:
            node: Starting node (None for root)
            
        Returns:
            List of import nodes
        """
        import_types = self.IMPORT_TYPES.get(self.language, set())
        return [n for n in self.walk(node) if n.type in import_types]
    
    def get_node_type(self, node: Node) -> str:
        """Get the type name of a tree-sitter node.
        
        Args:
            node: Tree-sitter Node
            
        Returns:
            Type name as string
        """
        return node.type
    
    def is_call_to(self, node: Node, func_name: str) -> bool:
        """Check if node is a call to a specific function.
        
        Args:
            node: Tree-sitter Node
            func_name: Function name to check
            
        Returns:
            True if node is a call to func_name
        """
        call_types = self.CALL_TYPES.get(self.language, set())
        if node.type not in call_types:
            return False
        
        call_name = self.get_call_name(node)
        return call_name == func_name or call_name.endswith(f".{func_name}")
    
    def get_call_name(self, node: Node) -> str:
        """Get the name of a function call.
        
        Args:
            node: Call node
            
        Returns:
            Function name
        """
        func = node.child_by_field_name("function") or node.child_by_field_name("name")
        if func:
            return self.get_node_text(func)
        return "<unknown_call>"
    
    def get_docstring(self, node: Node) -> Optional[str]:
        """Extract docstring/comment from a function definition.
        
        Args:
            node: Function definition node
            
        Returns:
            Docstring text if present, None otherwise
        """
        # Look for preceding comment
        if node.prev_sibling and node.prev_sibling.type in ("comment", "block_comment", "line_comment"):
            return self.get_node_text(node.prev_sibling)
        
        # Look for JSDoc-style comment in first child
        for child in node.children:
            if child.type in ("comment", "block_comment"):
                return self.get_node_text(child)
        
        return None
    
    def get_function_name(self, node: Node) -> str:
        """Get the name of a function definition.
        
        Args:
            node: Function definition node
            
        Returns:
            Function name
        """
        name_node = node.child_by_field_name("name")
        if name_node:
            return self.get_node_text(name_node)
        
        # For arrow functions assigned to variables
        if node.type == "arrow_function" and node.parent:
            if node.parent.type == "variable_declarator":
                name_node = node.parent.child_by_field_name("name")
                if name_node:
                    return self.get_node_text(name_node)
        
        return "<anonymous>"
    
    def get_function_parameters(self, node: Node) -> List[Dict[str, Any]]:
        """Get parameters from a function definition.
        
        Args:
            node: Function definition node
            
        Returns:
            List of parameter info dicts with 'name' and optional 'type'
        """
        params = []
        params_node = node.child_by_field_name("parameters")
        
        if not params_node:
            for child in node.children:
                if child.type in ("formal_parameters", "parameters", "parameter_list"):
                    params_node = child
                    break
        
        if not params_node:
            return params
        
        for child in params_node.children:
            if child.type in ("identifier", "formal_parameter", "required_parameter",
                             "parameter_declaration", "simple_parameter", "parameter"):
                param_info = {}
                
                # Get name
                name_node = child.child_by_field_name("name")
                if name_node:
                    param_info["name"] = self.get_node_text(name_node)
                elif child.type == "identifier":
                    param_info["name"] = self.get_node_text(child)
                else:
                    continue
                
                # Get type annotation if available
                type_node = child.child_by_field_name("type")
                if type_node:
                    param_info["type"] = self.get_node_text(type_node)
                
                params.append(param_info)
        
        return params
