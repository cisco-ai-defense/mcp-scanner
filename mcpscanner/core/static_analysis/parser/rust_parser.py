"""Rust parser using tree-sitter for MCP Scanner."""

from pathlib import Path
from typing import List, Optional
from tree_sitter import Node
import tree_sitter_rust as tsrust
from tree_sitter import Language, Parser

from .base import BaseParser


class RustParser(BaseParser):
    """Parser for Rust source code using tree-sitter."""
    
    def __init__(self, file_path: Path, source_code: str):
        """Initialize Rust parser.
        
        Args:
            file_path: Path to the Rust file
            source_code: Rust source code to parse
        """
        super().__init__(file_path, source_code)
        self._language = Language(tsrust.language())
        self._parser = Parser(self._language)
        self._root = None
    
    def parse(self) -> Optional[Node]:
        """Parse Rust source code into AST.
        
        Returns:
            Root node of the AST
        """
        tree = self._parser.parse(bytes(self.source_code, "utf8"))
        self._root = tree.root_node
        return self._root
    
    def walk(self, node: Optional[Node] = None) -> List[Node]:
        """Walk the AST and yield all nodes.
        
        Args:
            node: Starting node (uses root if None)
            
        Yields:
            AST nodes
        """
        if node is None:
            if self._root is None:
                self.parse()
            node = self._root
        
        if node is None:
            return
        
        yield node
        for child in node.children:
            yield from self.walk(child)
    
    def get_node_text(self, node: Node) -> str:
        """Get source text for a node.
        
        Args:
            node: AST node
            
        Returns:
            Source code text for the node
        """
        return self.source_code[node.start_byte:node.end_byte]
    
    def get_node_range(self, node: Node) -> tuple:
        """Get the line and column range for a node.
        
        Args:
            node: AST node
            
        Returns:
            Tuple of (start_line, start_col, end_line, end_col)
        """
        return (
            node.start_point[0] + 1,  # Line numbers are 1-indexed
            node.start_point[1],
            node.end_point[0] + 1,
            node.end_point[1]
        )
    
    def find_mcp_decorated_functions(self) -> List[Node]:
        """Find all MCP tool handler methods in the AST.
        
        In Rust MCP, tools are typically defined as:
        1. Methods in impl blocks for MCP services
        2. Functions that handle MCP requests
        3. Async functions that are part of the service
        
        Returns:
            List of function nodes that are MCP handlers
        """
        mcp_functions = []
        
        if self._root is None:
            self.parse()
        
        # Find all function definitions
        for node in self.walk():
            if node.type == 'function_item':
                # Check if it's an async function or has MCP-related attributes
                if self._is_mcp_function(node):
                    mcp_functions.append(node)
            
            # Also look for methods in impl blocks
            elif node.type == 'impl_item':
                methods = self._find_methods_in_impl(node)
                mcp_functions.extend(methods)
        
        return mcp_functions
    
    def _is_mcp_function(self, func_node: Node) -> bool:
        """Check if a function is MCP-related.
        
        Args:
            func_node: Function node
            
        Returns:
            True if function appears to be MCP-related
        """
        func_text = self.get_node_text(func_node)
        
        # Check for async functions (common in MCP servers)
        if 'async' in func_text[:100]:
            return True
        
        # Check for MCP-related names or attributes
        mcp_indicators = ['mcp', 'tool', 'handler', 'service', 'request']
        for indicator in mcp_indicators:
            if indicator in func_text.lower():
                return True
        
        return False
    
    def _find_methods_in_impl(self, impl_node: Node) -> List[Node]:
        """Find methods in an impl block.
        
        Args:
            impl_node: Impl block node
            
        Returns:
            List of method nodes
        """
        methods = []
        
        for child in impl_node.children:
            if child.type == 'declaration_list':
                for item in child.children:
                    if item.type == 'function_item':
                        # Include all public methods
                        if self._is_public_method(item):
                            methods.append(item)
        
        return methods
    
    def _is_public_method(self, func_node: Node) -> bool:
        """Check if a function/method is public.
        
        Args:
            func_node: Function node
            
        Returns:
            True if public
        """
        # Check for pub keyword
        for child in func_node.children:
            if child.type == 'visibility_modifier':
                return True
        
        # If no visibility modifier in impl block, it's private by default
        # But for MCP detection, we'll be lenient and include it
        return True
    
    def extract_comment(self, node: Node) -> Optional[str]:
        """Extract documentation comment for a function.
        
        Args:
            node: Function node
            
        Returns:
            Documentation comment text or None
        """
        # Rust uses /// or //! for doc comments
        start_line = node.start_point[0]
        
        lines = self.source_code.split('\n')
        doc_lines = []
        
        for i in range(start_line - 1, -1, -1):
            line = lines[i].strip()
            if line.startswith('///') or line.startswith('//!'):
                # Remove /// or //! and add to doc
                doc_lines.insert(0, line[3:].strip())
            elif line.startswith('//'):
                # Regular comment, might still be documentation
                doc_lines.insert(0, line[2:].strip())
            elif line and not line.startswith('#['):
                # Stop at non-comment, non-attribute line
                break
        
        if doc_lines:
            return '\n'.join(doc_lines)
        
        return None
