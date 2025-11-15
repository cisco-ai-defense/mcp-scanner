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

"""Unified AST representation for multi-language support.

This module provides a language-agnostic AST representation that normalizes
Python, JavaScript, and TypeScript ASTs into a common format for analysis.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class NodeType(Enum):
    """Unified AST node types."""
    
    # Program structure
    MODULE = "module"
    FUNCTION = "function"
    CLASS = "class"
    
    # Statements
    ASSIGNMENT = "assignment"
    RETURN = "return"
    IF = "if"
    WHILE = "while"
    FOR = "for"
    TRY = "try"
    EXCEPT = "except"
    FINALLY = "finally"
    
    # Expressions
    CALL = "call"
    BINARY_OP = "binary_op"
    UNARY_OP = "unary_op"
    MEMBER_ACCESS = "member_access"
    SUBSCRIPT = "subscript"
    
    # Literals
    LITERAL = "literal"
    OBJECT_LITERAL = "object_literal"
    ARRAY_LITERAL = "array_literal"
    PROPERTY = "property"
    IDENTIFIER = "identifier"
    
    # Async/Await
    ASYNC_FUNCTION = "async_function"
    AWAIT = "await"
    
    # Control flow
    BLOCK = "block"
    CONDITIONAL = "conditional"
    
    # Other
    IMPORT = "import"
    EXPORT = "export"
    DECORATOR = "decorator"
    STATEMENT = "statement"
    UNKNOWN = "unknown"


@dataclass
class SourceLocation:
    """Source code location information."""
    
    line: int
    column: int
    end_line: int
    end_column: int


@dataclass
class UnifiedASTNode:
    """Language-agnostic AST node.
    
    This represents a single node in the unified AST, with fields that
    are common across Python, JavaScript, and TypeScript.
    """
    
    type: NodeType
    name: Optional[str] = None
    value: Optional[Any] = None
    children: List['UnifiedASTNode'] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    location: Optional[SourceLocation] = None
    
    # Function-specific fields
    parameters: List[str] = field(default_factory=list)
    return_type: Optional[str] = None
    is_async: bool = False
    is_generator: bool = False
    
    # Decorator/annotation fields
    decorators: List[str] = field(default_factory=list)
    
    # Documentation
    docstring: Optional[str] = None
    jsdoc: Optional[str] = None
    
    def add_child(self, child: 'UnifiedASTNode') -> None:
        """Add a child node."""
        self.children.append(child)
    
    def get_children_by_type(self, node_type: NodeType) -> List['UnifiedASTNode']:
        """Get all children of a specific type."""
        return [child for child in self.children if child.type == node_type]
    
    def walk(self) -> List['UnifiedASTNode']:
        """Walk the AST tree and return all nodes."""
        nodes = [self]
        for child in self.children:
            nodes.extend(child.walk())
        return nodes
    
    def find_by_name(self, name: str) -> Optional['UnifiedASTNode']:
        """Find a node by name."""
        if self.name == name:
            return self
        for child in self.children:
            result = child.find_by_name(name)
            if result:
                return result
        return None
    
    def __repr__(self) -> str:
        """String representation."""
        name_part = f" '{self.name}'" if self.name else ""
        value_part = f" = {self.value}" if self.value else ""
        return f"<{self.type.value}{name_part}{value_part}>"


class ASTNormalizer(ABC):
    """Abstract base class for AST normalizers.
    
    Each language (Python, JavaScript, TypeScript) implements its own
    normalizer to convert language-specific ASTs to the unified format.
    """
    
    @abstractmethod
    def normalize(self, native_ast: Any) -> UnifiedASTNode:
        """Convert language-specific AST to unified format.
        
        Args:
            native_ast: Language-specific AST node
            
        Returns:
            Unified AST node
        """
        pass
    
    @abstractmethod
    def normalize_function(self, node: Any) -> UnifiedASTNode:
        """Normalize a function definition.
        
        Args:
            node: Language-specific function node
            
        Returns:
            Unified function node
        """
        pass
    
    @abstractmethod
    def normalize_call(self, node: Any) -> UnifiedASTNode:
        """Normalize a function call.
        
        Args:
            node: Language-specific call node
            
        Returns:
            Unified call node
        """
        pass
    
    @abstractmethod
    def normalize_assignment(self, node: Any) -> UnifiedASTNode:
        """Normalize an assignment statement.
        
        Args:
            node: Language-specific assignment node
            
        Returns:
            Unified assignment node
        """
        pass
    
    def extract_location(self, node: Any) -> Optional[SourceLocation]:
        """Extract source location from node.
        
        Args:
            node: Language-specific node
            
        Returns:
            Source location or None
        """
        # Override in subclasses
        return None


@dataclass
class FunctionSignature:
    """Unified function signature representation."""
    
    name: str
    parameters: List[Dict[str, Any]]  # [{name, type, default}, ...]
    return_type: Optional[str]
    is_async: bool
    is_generator: bool
    decorators: List[str]
    docstring: Optional[str]
    location: Optional[SourceLocation]


class UnifiedASTVisitor(ABC):
    """Visitor pattern for traversing unified AST."""
    
    def visit(self, node: UnifiedASTNode) -> Any:
        """Visit a node and dispatch to specific handler.
        
        Args:
            node: Node to visit
            
        Returns:
            Result from handler
        """
        method_name = f"visit_{node.type.value}"
        visitor = getattr(self, method_name, self.generic_visit)
        return visitor(node)
    
    def generic_visit(self, node: UnifiedASTNode) -> Any:
        """Default visitor for unhandled node types.
        
        Args:
            node: Node to visit
            
        Returns:
            None
        """
        for child in node.children:
            self.visit(child)
    
    def visit_function(self, node: UnifiedASTNode) -> Any:
        """Visit a function node."""
        return self.generic_visit(node)
    
    def visit_call(self, node: UnifiedASTNode) -> Any:
        """Visit a call node."""
        return self.generic_visit(node)
    
    def visit_assignment(self, node: UnifiedASTNode) -> Any:
        """Visit an assignment node."""
        return self.generic_visit(node)
