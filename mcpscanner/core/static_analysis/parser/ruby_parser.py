"""Ruby parser using tree-sitter for MCP Scanner."""

from pathlib import Path
from typing import List, Optional
from tree_sitter import Node
import tree_sitter_ruby as tsruby
from tree_sitter import Language, Parser

from .base import BaseParser


class RubyParser(BaseParser):
    """Parser for Ruby source code using tree-sitter."""
    
    def __init__(self, file_path: Path, source_code: str):
        """Initialize Ruby parser.
        
        Args:
            file_path: Path to the Ruby file
            source_code: Ruby source code to parse
        """
        super().__init__(file_path, source_code)
        self._language = Language(tsruby.language())
        self._parser = Parser(self._language)
        self._root = None
    
    def parse(self) -> Optional[Node]:
        """Parse Ruby source code into AST.
        
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
        
        In Ruby MCP, tools are defined as:
        1. Classes that inherit from MCP::Tool with a call method
        2. server.define_tool blocks
        
        Returns:
            List of method/block nodes that are MCP handlers
        """
        mcp_functions = []
        
        if self._root is None:
            self.parse()
        
        # Find classes that inherit from MCP::Tool
        for node in self.walk():
            if node.type == 'class':
                if self._is_mcp_tool_class(node):
                    # Find the call method in this class
                    call_method = self._find_call_method(node)
                    if call_method:
                        mcp_functions.append(call_method)
        
        # Find server.define_tool blocks
        for node in self.walk():
            if node.type == 'call':
                if self._is_define_tool_call(node):
                    # Extract the block
                    block = self._extract_block_from_call(node)
                    if block:
                        mcp_functions.append(block)
        
        return mcp_functions
    
    def _is_mcp_tool_class(self, class_node: Node) -> bool:
        """Check if a class inherits from MCP::Tool.
        
        Args:
            class_node: Class node
            
        Returns:
            True if class inherits from MCP::Tool
        """
        for child in class_node.children:
            if child.type == 'superclass':
                superclass_text = self.get_node_text(child)
                if 'MCP::Tool' in superclass_text or 'MCP::Prompt' in superclass_text:
                    return True
        return False
    
    def _find_call_method(self, class_node: Node) -> Optional[Node]:
        """Find the call method in a class.
        
        Args:
            class_node: Class node
            
        Returns:
            Method node or None
        """
        for child in class_node.children:
            if child.type == 'body_statement':
                for stmt in child.children:
                    # Check direct methods
                    if stmt.type in ['singleton_method', 'method']:
                        for method_child in stmt.children:
                            if method_child.type == 'identifier':
                                if self.get_node_text(method_child) == 'call':
                                    return stmt
                    
                    # Check inside singleton_class (class << self)
                    elif stmt.type == 'singleton_class':
                        for singleton_child in stmt.children:
                            if singleton_child.type == 'body_statement':
                                for method in singleton_child.children:
                                    if method.type in ['method', 'singleton_method']:
                                        for method_child in method.children:
                                            if method_child.type == 'identifier':
                                                if self.get_node_text(method_child) == 'call':
                                                    return method
        return None
    
    def _is_define_tool_call(self, call_node: Node) -> bool:
        """Check if a call is server.define_tool.
        
        Args:
            call_node: Call node
            
        Returns:
            True if this is a define_tool call
        """
        call_text = self.get_node_text(call_node)
        return 'define_tool' in call_text
    
    def _extract_block_from_call(self, call_node: Node) -> Optional[Node]:
        """Extract the block from a method call.
        
        Args:
            call_node: Call node
            
        Returns:
            Block node or None
        """
        for child in call_node.children:
            if child.type in ['block', 'do_block']:
                return child
        return None
    
    def extract_comment(self, node: Node) -> Optional[str]:
        """Extract comment/documentation for a method.
        
        Args:
            node: Method node
            
        Returns:
            Documentation comment text or None
        """
        # Ruby uses # for comments
        # Look for comments before the method
        start_line = node.start_point[0]
        
        lines = self.source_code.split('\n')
        doc_lines = []
        
        for i in range(start_line - 1, -1, -1):
            line = lines[i].strip()
            if line.startswith('#'):
                # Remove # and add to doc
                doc_lines.insert(0, line[1:].strip())
            elif line and not line.startswith('class') and not line.startswith('def'):
                # Stop at non-comment, non-empty line
                break
        
        if doc_lines:
            return '\n'.join(doc_lines)
        
        return None
