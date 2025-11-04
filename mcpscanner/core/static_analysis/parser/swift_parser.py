"""Swift parser using tree-sitter."""

from pathlib import Path
from typing import List, Optional
from tree_sitter import Node, Parser, Language as TSLanguage
import tree_sitter_swift

from .base import BaseParser


class SwiftParser(BaseParser):
    """Parser for Swift using tree-sitter."""
    
    def __init__(self, file_path: Path, source_code: str):
        """Initialize Swift parser.
        
        Args:
            file_path: Path to Swift file
            source_code: Swift source code
        """
        super().__init__(file_path, source_code)
        self._parser = Parser(TSLanguage(tree_sitter_swift.language()))
        self._root = None
    
    def parse(self) -> Node:
        """Parse Swift source code.
        
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
        
        In Swift MCP, tools are registered via:
        await server.withMethodHandler(CallTool.self) { params in ... }
        
        We look for closure expressions passed to withMethodHandler.
        For CallTool handlers with switch statements, we extract individual cases.
        
        Returns:
            List of closure/function nodes that are MCP handlers
        """
        mcp_functions = []
        
        if self._root is None:
            self.parse()
        
        # Look for withMethodHandler calls and extract the closure
        for node in self.walk():
            if node.type == 'call_expression':
                if self._is_with_method_handler_call(node):
                    # Extract the closure (trailing closure or argument)
                    closure = self._extract_closure_from_call(node)
                    if closure:
                        # Check if this is a CallTool handler with switch cases
                        # If so, extract individual tool handlers from switch cases
                        tool_cases = self._extract_switch_cases(closure)
                        if tool_cases:
                            mcp_functions.extend(tool_cases)
                        else:
                            mcp_functions.append(closure)
        
        return mcp_functions
    
    def _extract_switch_cases(self, closure: Node) -> List[Node]:
        """Extract individual tool handlers from switch cases.
        
        Args:
            closure: Closure node
            
        Returns:
            List of switch case nodes, or empty list if no switch found
        """
        cases = []
        
        # Look for switch statements in the closure
        for child in closure.children:
            if child.type == 'statements':
                for stmt in child.children:
                    if stmt.type == 'switch_statement':
                        # Extract case statements
                        for switch_child in stmt.children:
                            if switch_child.type == 'switch_entry':
                                # Store the case with metadata about the tool name
                                cases.append(switch_child)
        
        return cases
    
    def _is_with_method_handler_call(self, node: Node) -> bool:
        """Check if a call expression is a withMethodHandler call.
        
        Args:
            node: Call expression node
            
        Returns:
            True if this is a withMethodHandler call
        """
        # Check if the call includes "withMethodHandler"
        text = self.get_node_text(node)
        return 'withMethodHandler' in text or 'withTool' in text
    
    def _extract_closure_from_call(self, node: Node) -> Optional[Node]:
        """Extract the closure from a withMethodHandler call.
        
        Args:
            node: Call expression node
            
        Returns:
            Closure expression node or None
        """
        # Swift can have trailing closures or closures in argument lists
        for child in node.children:
            # Trailing closure
            if child.type in ['closure_expression', 'lambda_literal']:
                return child
            # Closure in argument list
            elif child.type == 'call_suffix':
                for subchild in child.children:
                    if subchild.type in ['closure_expression', 'lambda_literal']:
                        return subchild
                    elif subchild.type == 'value_arguments':
                        for arg in subchild.children:
                            if arg.type == 'value_argument':
                                for val in arg.children:
                                    if val.type in ['closure_expression', 'lambda_literal']:
                                        return val
        return None
    
    def extract_comment(self, node: Node) -> Optional[str]:
        """Extract comment/documentation for a function.
        
        Args:
            node: Function node
            
        Returns:
            Comment string or None
        """
        # Look for comment before the node
        if node.prev_sibling and 'comment' in node.prev_sibling.type:
            return self.get_node_text(node.prev_sibling)
        
        # Also check parent for comments
        if node.parent:
            for child in node.parent.children:
                if 'comment' in child.type and child.start_byte < node.start_byte:
                    return self.get_node_text(child)
        
        return None
