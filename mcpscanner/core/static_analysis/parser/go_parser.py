"""Go parser using tree-sitter."""

from pathlib import Path
from typing import List, Optional
from tree_sitter import Node, Parser, Language as TSLanguage
import tree_sitter_go

from .base import BaseParser


class GoParser(BaseParser):
    """Parser for Go using tree-sitter."""
    
    def __init__(self, file_path: Path, source_code: str):
        """Initialize Go parser.
        
        Args:
            file_path: Path to Go file
            source_code: Go source code
        """
        super().__init__(file_path, source_code)
        self._parser = Parser(TSLanguage(tree_sitter_go.language()))
        self._root = None
    
    def parse(self) -> Node:
        """Parse Go source code.
        
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
        """Find all MCP tool handler functions in the AST.
        
        In Go, MCP tools are registered via:
        mcp.AddTool(server, &mcp.Tool{...}, handlerFunc)
        
        We look for function declarations that are passed to AddTool.
        
        Returns:
            List of function declaration nodes that are MCP handlers
        """
        mcp_functions = []
        handler_names = set()
        
        if self._root is None:
            self.parse()
        
        # First pass: find all AddTool calls and collect handler function names
        for node in self.walk():
            if node.type == 'call_expression':
                # Check if this is an AddTool call
                if self._is_add_tool_call(node):
                    # Extract the handler function name (3rd argument)
                    handler_name = self._extract_handler_name_from_add_tool(node)
                    if handler_name:
                        handler_names.add(handler_name)
        
        # Second pass: find all function declarations with those names
        for node in self.walk():
            if node.type == 'function_declaration':
                for child in node.children:
                    if child.type == 'identifier':
                        func_name = self.get_node_text(child)
                        if func_name in handler_names:
                            mcp_functions.append(node)
                        break
        
        return mcp_functions
    
    def _is_add_tool_call(self, node: Node) -> bool:
        """Check if a call expression is an mcp.AddTool call.
        
        Args:
            node: Call expression node
            
        Returns:
            True if this is an AddTool call
        """
        # Get the function being called
        for child in node.children:
            if child.type == 'selector_expression':
                # Check if it's mcp.AddTool or similar
                text = self.get_node_text(child)
                if 'AddTool' in text or 'addTool' in text:
                    return True
        return False
    
    def _extract_handler_name_from_add_tool(self, node: Node) -> Optional[str]:
        """Extract the handler function name from an AddTool call.
        
        Args:
            node: AddTool call expression node
            
        Returns:
            Handler function name or None
        """
        # Find the argument_list
        for child in node.children:
            if child.type == 'argument_list':
                # The handler is typically the 3rd argument
                # mcp.AddTool(server, &mcp.Tool{...}, handlerFunc)
                # Filter out parentheses and commas
                args = [c for c in child.children if c.type not in [',', '(', ')']]
                if len(args) >= 3:
                    handler = args[2]
                    # If it's an identifier, return the function name
                    if handler.type == 'identifier':
                        return self.get_node_text(handler)
        return None
    
    def _extract_handler_from_add_tool(self, node: Node) -> Optional[Node]:
        """Extract the handler function from an AddTool call.
        
        Args:
            node: AddTool call expression node
            
        Returns:
            Handler function node or None
        """
        # Find the argument_list
        for child in node.children:
            if child.type == 'argument_list':
                # The handler is typically the 3rd argument
                # mcp.AddTool(server, &mcp.Tool{...}, handlerFunc)
                args = [c for c in child.children if c.type != ',']
                if len(args) >= 3:
                    handler = args[2]
                    # If it's an identifier, find the function declaration
                    if handler.type == 'identifier':
                        func_name = self.get_node_text(handler)
                        return self._find_function_by_name(func_name)
                    # If it's a function literal (anonymous function)
                    elif handler.type == 'func_literal':
                        return handler
        return None
    
    def _find_function_by_name(self, func_name: str) -> Optional[Node]:
        """Find a function declaration by name.
        
        Args:
            func_name: Name of the function
            
        Returns:
            Function declaration node or None
        """
        for node in self.walk():
            if node.type == 'function_declaration':
                for child in node.children:
                    if child.type == 'identifier':
                        if self.get_node_text(child) == func_name:
                            return node
        return None
    
    def extract_comment(self, node: Node) -> Optional[str]:
        """Extract comment/documentation for a function.
        
        Args:
            node: Function node
            
        Returns:
            Comment string or None
        """
        # Look for comment before the node
        if node.prev_sibling and node.prev_sibling.type == 'comment':
            return self.get_node_text(node.prev_sibling)
        
        # Also check parent for comments
        if node.parent:
            for child in node.parent.children:
                if child.type == 'comment' and child.start_byte < node.start_byte:
                    return self.get_node_text(child)
        
        return None
