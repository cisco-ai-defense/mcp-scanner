"""C# parser using tree-sitter for MCP Scanner."""

from pathlib import Path
from typing import List, Optional
from tree_sitter import Node
import tree_sitter_c_sharp as tscsharp
from tree_sitter import Language, Parser

from .base import BaseParser


class CSharpParser(BaseParser):
    """Parser for C# source code using tree-sitter."""
    
    def __init__(self, file_path: Path, source_code: str):
        """Initialize C# parser.
        
        Args:
            file_path: Path to the C# file
            source_code: C# source code to parse
        """
        super().__init__(file_path, source_code)
        self._language = Language(tscsharp.language())
        self._parser = Parser(self._language)
        self._root = None
    
    def parse(self) -> Optional[Node]:
        """Parse C# source code into AST.
        
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
        
        In C# MCP, tools are defined as methods with [McpServerTool] attribute:
        
        [McpServerTool(Name = "echo"), Description("Echoes the message")]
        public static string Echo(string message) => $"Echo: {message}";
        
        Returns:
            List of method nodes that are MCP handlers
        """
        mcp_functions = []
        
        if self._root is None:
            self.parse()
        
        # Look for methods with McpServerTool attribute
        for node in self.walk():
            if node.type == 'method_declaration':
                if self._has_mcp_attribute(node):
                    mcp_functions.append(node)
        
        return mcp_functions
    
    def _has_mcp_attribute(self, method_node: Node) -> bool:
        """Check if a method has McpServerTool attribute.
        
        Args:
            method_node: Method declaration node
            
        Returns:
            True if method has McpServerTool attribute
        """
        # Look for attribute_list before the method
        for child in method_node.children:
            if child.type == 'attribute_list':
                text = self.get_node_text(child)
                if 'McpServerTool' in text:
                    return True
        return False
    
    def extract_comment(self, node: Node) -> Optional[str]:
        """Extract XML documentation comment for a method.
        
        Args:
            node: Method node
            
        Returns:
            Documentation comment text or None
        """
        # C# uses XML documentation comments (///)
        # Look for comment nodes before the method
        start_line = node.start_point[0]
        
        # Search backwards from method start for XML doc comments
        lines = self.source_code.split('\n')
        doc_lines = []
        
        for i in range(start_line - 1, -1, -1):
            line = lines[i].strip()
            if line.startswith('///'):
                # Remove /// and add to doc
                doc_lines.insert(0, line[3:].strip())
            elif line and not line.startswith('['):
                # Stop at non-comment, non-attribute line
                break
        
        if doc_lines:
            return '\n'.join(doc_lines)
        
        return None
