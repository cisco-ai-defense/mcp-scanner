"""Kotlin parser using tree-sitter."""

from pathlib import Path
from typing import List, Optional
from tree_sitter import Node, Parser, Language as TSLanguage
import tree_sitter_kotlin

from .base import BaseParser


class KotlinParser(BaseParser):
    """Parser for Kotlin using tree-sitter."""
    
    def __init__(self, file_path: Path, source_code: str):
        """Initialize Kotlin parser.
        
        Args:
            file_path: Path to Kotlin file
            source_code: Kotlin source code
        """
        super().__init__(file_path, source_code)
        self._parser = Parser(TSLanguage(tree_sitter_kotlin.language()))
        self._root = None
    
    def parse(self) -> Node:
        """Parse Kotlin source code.
        
        Returns:
            Root AST node
        """
        tree = self._parser.parse(bytes(self.source_code, "utf8"))
        self._root = tree.root_node
        return self._root
    
    def walk(self):
        """Walk the AST.
        
        Yields:
            AST nodes
        """
        if self._root is None:
            self.parse()
        
        def _walk(node):
            yield node
            for child in node.children:
                yield from _walk(child)
        
        yield from _walk(self._root)
    
    def get_node_range(self, node: Node):
        """Get source range for a tree-sitter node.
        
        Args:
            node: Tree-sitter node
            
        Returns:
            Source range
        """
        from ..types import Range
        return Range(
            start_line=node.start_point[0] + 1,  # tree-sitter is 0-indexed
            start_column=node.start_point[1],
            end_line=node.end_point[0] + 1,
            end_column=node.end_point[1]
        )
    
    def get_node_text(self, node: Node) -> str:
        """Get text content of a node.
        
        Args:
            node: Tree-sitter node
            
        Returns:
            Text content
        """
        return self.source_code[node.start_byte:node.end_byte]
    
    def find_mcp_decorated_functions(self) -> List[Node]:
        """Find all MCP-related functions in the AST.
        
        Looks for lambda expressions that are MCP tool/resource/prompt handlers.
        These are typically passed to registerTool, registerResource, or registerPrompt.
        
        Returns:
            List of lambda expression nodes that are MCP handlers
        """
        mcp_functions = []
        
        if self._root is None:
            self.parse()
        
        # Look for lambda expressions that are MCP tool handlers
        # Pattern: server.registerTool(Tool(...)) { request -> ... }
        # Or: RegisteredTool(tool = Tool(...), handler = { request -> ... })
        for node in self.walk():
            if node.type == 'lambda_literal':
                # Check if this lambda is inside an MCP registration
                if self._is_tool_handler_lambda(node):
                    mcp_functions.append(node)
        
        return mcp_functions
    
    def _is_tool_handler_lambda(self, node: Node) -> bool:
        """Check if a lambda expression is an MCP tool handler.
        
        Args:
            node: Lambda expression node
            
        Returns:
            True if lambda is an MCP tool handler
        """
        # Walk up the tree to find if we're inside an MCP registration
        current = node.parent
        while current:
            node_text = self.get_node_text(current)
            # Check for MCP registration patterns
            if any(pattern in node_text for pattern in [
                'registerTool',
                'registerResource',
                'registerPrompt',
                'RegisteredTool',
                'RegisteredResource',
                'RegisteredPrompt',
                'addTool',
                'addResource',
                'addPrompt',
            ]):
                return True
            current = current.parent
        return False
    
    def extract_kdoc(self, node: Node) -> Optional[str]:
        """Extract KDoc comment for a function.
        
        Args:
            node: Function node
            
        Returns:
            KDoc string or None
        """
        # Look for KDoc comment before the node
        if node.prev_sibling and node.prev_sibling.type == 'comment':
            comment_text = self.get_node_text(node.prev_sibling)
            if comment_text.startswith('/**'):
                return comment_text
        
        # Also check parent for comments
        if node.parent:
            for child in node.parent.children:
                if child.type == 'comment' and child.start_byte < node.start_byte:
                    comment_text = self.get_node_text(child)
                    if comment_text.startswith('/**'):
                        return comment_text
        
        return None
