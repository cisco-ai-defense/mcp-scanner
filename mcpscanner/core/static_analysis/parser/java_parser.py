"""Java source code parser using tree-sitter."""

from pathlib import Path
from typing import List, Optional
from tree_sitter import Language, Parser, Node
import tree_sitter_java as tsjava

from .base import BaseParser


class JavaParser(BaseParser):
    """Parser for Java code using tree-sitter."""
    
    def __init__(self, file_path: Path, source_code: str):
        """Initialize Java parser.
        
        Args:
            file_path: Path to the Java source file
            source_code: Java source code content
        """
        super().__init__(file_path, source_code)
        self._language = Language(tsjava.language())
        self._parser = Parser(self._language)
        self._tree = None
        self._root = None
    
    def parse(self) -> Node:
        """Parse Java source code into AST.
        
        Returns:
            Root node of the AST
        """
        if self._tree is None:
            self._tree = self._parser.parse(bytes(self.source_code, "utf8"))
            self._root = self._tree.root_node
        return self._root
    
    def walk(self):
        """Walk through all nodes in the AST.
        
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
        """Find all MCP-annotated methods in the AST.
        
        Looks for lambda expressions that are tool/resource/prompt handlers.
        These are typically the second argument to SyncToolSpecification or AsyncToolSpecification.
        
        Returns:
            List of lambda expression nodes that are MCP handlers
        """
        mcp_functions = []
        
        if self._root is None:
            self.parse()
        
        # Look for lambda expressions that are MCP tool handlers
        # Pattern: new SyncToolSpecification(tool, (exchange, arguments) -> { ... })
        for node in self.walk():
            if node.type == 'lambda_expression':
                # Check if this lambda is inside a tool specification
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
        # Walk up the tree to find if we're inside a tool specification
        current = node.parent
        while current:
            node_text = self.get_node_text(current)
            # Check for MCP specification patterns
            if any(pattern in node_text for pattern in [
                'SyncToolSpecification',
                'AsyncToolSpecification',
                'SyncResourceSpecification',
                'AsyncResourceSpecification',
                'SyncPromptSpecification',
                'AsyncPromptSpecification',
            ]):
                return True
            current = current.parent
        return False
    
    def _is_mcp_method(self, node: Node) -> bool:
        """Check if a method is MCP-related.
        
        Args:
            node: Method declaration node
            
        Returns:
            True if method is MCP-related
        """
        # Check for @Bean annotation (Spring configuration)
        for child in node.children:
            if child.type == 'modifiers':
                for modifier in child.children:
                    if modifier.type == 'marker_annotation' or modifier.type == 'annotation':
                        annotation_text = self.get_node_text(modifier)
                        if '@Bean' in annotation_text:
                            return True
        
        # Check method name for MCP patterns
        method_name = self._get_method_name(node)
        if method_name:
            mcp_patterns = [
                'tool', 'Tool',
                'resource', 'Resource',
                'prompt', 'Prompt',
                'mcp', 'Mcp', 'MCP',
                'server', 'Server',
            ]
            if any(pattern in method_name for pattern in mcp_patterns):
                return True
        
        # Check return type for MCP types
        return_type = self._get_return_type(node)
        if return_type:
            mcp_types = [
                'McpSyncServer', 'McpAsyncServer',
                'SyncToolSpecification', 'AsyncToolSpecification',
                'SyncResourceSpecification', 'AsyncResourceSpecification',
                'SyncPromptSpecification', 'AsyncPromptSpecification',
            ]
            if any(mcp_type in return_type for mcp_type in mcp_types):
                return True
        
        return False
    
    def _is_mcp_registration(self, node: Node) -> bool:
        """Check if node is an MCP registration call.
        
        Args:
            node: AST node
            
        Returns:
            True if node is MCP registration
        """
        # Look for method invocations like addTool, addResource, addPrompt
        if node.type == 'method_invocation':
            method_text = self.get_node_text(node)
            mcp_methods = [
                'addTool', 'tool',
                'addResource', 'resource',
                'addPrompt', 'prompt',
                'registerTool', 'registerResource', 'registerPrompt',
            ]
            return any(method in method_text for method in mcp_methods)
        
        return False
    
    def _get_method_name(self, node: Node) -> Optional[str]:
        """Extract method name from method declaration.
        
        Args:
            node: Method declaration node
            
        Returns:
            Method name or None
        """
        for child in node.children:
            if child.type == 'identifier':
                return self.get_node_text(child)
        return None
    
    def _get_return_type(self, node: Node) -> Optional[str]:
        """Extract return type from method declaration.
        
        Args:
            node: Method declaration node
            
        Returns:
            Return type as string or None
        """
        for child in node.children:
            if child.type in ['type_identifier', 'generic_type', 'scoped_type_identifier']:
                return self.get_node_text(child)
        return None
    
    def extract_javadoc(self, node: Node) -> Optional[str]:
        """Extract Javadoc comment for a method.
        
        Args:
            node: Method node
            
        Returns:
            Javadoc text or None
        """
        # Look for block comment before the method
        prev_sibling = node.prev_sibling
        while prev_sibling:
            if prev_sibling.type == 'block_comment':
                comment_text = self.get_node_text(prev_sibling)
                if comment_text.startswith('/**'):
                    return comment_text
            elif prev_sibling.type not in ['block_comment', 'line_comment']:
                # Stop if we hit a non-comment node
                break
            prev_sibling = prev_sibling.prev_sibling
        
        return None
    
    def find_calls(self, node: Node) -> List[Node]:
        """Find all method calls in a node.
        
        Args:
            node: Node to search
            
        Returns:
            List of method invocation nodes
        """
        calls = []
        
        def _find_calls(n):
            if n.type == 'method_invocation':
                calls.append(n)
            for child in n.children:
                _find_calls(child)
        
        _find_calls(node)
        return calls
