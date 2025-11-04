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

"""Python AST normalizer."""

import ast
from typing import Any, List, Optional

from ..unified_ast import (
    ASTNormalizer,
    NodeType,
    SourceLocation,
    UnifiedASTNode,
)


class PythonASTNormalizer(ASTNormalizer):
    """Normalizes Python AST to unified format."""
    
    def normalize(self, native_ast: ast.AST) -> UnifiedASTNode:
        """Convert Python AST to unified format.
        
        Args:
            native_ast: Python AST node
            
        Returns:
            Unified AST node
        """
        if isinstance(native_ast, ast.Module):
            return self._normalize_module(native_ast)
        elif isinstance(native_ast, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return self.normalize_function(native_ast)
        elif isinstance(native_ast, ast.ClassDef):
            return self._normalize_class(native_ast)
        elif isinstance(native_ast, ast.Assign):
            return self.normalize_assignment(native_ast)
        elif isinstance(native_ast, ast.Call):
            return self.normalize_call(native_ast)
        elif isinstance(native_ast, ast.Return):
            return self._normalize_return(native_ast)
        elif isinstance(native_ast, ast.If):
            return self._normalize_if(native_ast)
        elif isinstance(native_ast, ast.While):
            return self._normalize_while(native_ast)
        elif isinstance(native_ast, ast.For):
            return self._normalize_for(native_ast)
        elif isinstance(native_ast, ast.Try):
            return self._normalize_try(native_ast)
        elif isinstance(native_ast, (ast.Import, ast.ImportFrom)):
            return self._normalize_import(native_ast)
        elif isinstance(native_ast, ast.Name):
            return self._normalize_name(native_ast)
        elif isinstance(native_ast, ast.Constant):
            return self._normalize_constant(native_ast)
        elif isinstance(native_ast, ast.BinOp):
            return self._normalize_binop(native_ast)
        elif isinstance(native_ast, ast.Attribute):
            return self._normalize_attribute(native_ast)
        elif isinstance(native_ast, ast.Subscript):
            return self._normalize_subscript(native_ast)
        elif isinstance(native_ast, ast.Await):
            return self._normalize_await(native_ast)
        else:
            # Generic fallback
            node = UnifiedASTNode(
                type=NodeType.UNKNOWN,
                metadata={"python_type": type(native_ast).__name__},
                location=self.extract_location(native_ast)
            )
            # Try to normalize children
            for child in ast.iter_child_nodes(native_ast):
                node.add_child(self.normalize(child))
            return node
    
    def normalize_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> UnifiedASTNode:
        """Normalize a function definition."""
        is_async = isinstance(node, ast.AsyncFunctionDef)
        
        # Extract parameters
        params = []
        for arg in node.args.args:
            params.append(arg.arg)
        
        # Extract decorators
        decorators = []
        for dec in node.decorator_list:
            try:
                decorators.append(ast.unparse(dec))
            except (AttributeError, TypeError, ValueError):
                decorators.append("<unknown_decorator>")
        
        # Extract docstring
        docstring = ast.get_docstring(node)
        
        # Extract return type
        return_type = None
        if node.returns:
            try:
                return_type = ast.unparse(node.returns)
            except (AttributeError, TypeError, ValueError):
                return_type = "<unknown>"
        
        func_node = UnifiedASTNode(
            type=NodeType.ASYNC_FUNCTION if is_async else NodeType.FUNCTION,
            name=node.name,
            parameters=params,
            return_type=return_type,
            is_async=is_async,
            is_generator=any(isinstance(n, (ast.Yield, ast.YieldFrom)) for n in ast.walk(node)),
            decorators=decorators,
            docstring=docstring,
            location=self.extract_location(node),
            metadata={"python_node": node}
        )
        
        # Normalize body
        for stmt in node.body:
            func_node.add_child(self.normalize(stmt))
        
        return func_node
    
    def normalize_call(self, node: ast.Call) -> UnifiedASTNode:
        """Normalize a function call."""
        # Extract function name
        func_name = None
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            try:
                func_name = ast.unparse(node.func)
            except (AttributeError, TypeError, ValueError):
                func_name = "<unknown_call>"
        
        call_node = UnifiedASTNode(
            type=NodeType.CALL,
            name=func_name,
            location=self.extract_location(node),
            metadata={"python_node": node}
        )
        
        # Normalize arguments
        for arg in node.args:
            call_node.add_child(self.normalize(arg))
        
        return call_node
    
    def normalize_assignment(self, node: ast.Assign) -> UnifiedASTNode:
        """Normalize an assignment statement."""
        # Extract target names
        targets = []
        for target in node.targets:
            if isinstance(target, ast.Name):
                targets.append(target.id)
            else:
                try:
                    targets.append(ast.unparse(target))
                except (AttributeError, TypeError, ValueError):
                    targets.append("<complex_target>")
        
        assign_node = UnifiedASTNode(
            type=NodeType.ASSIGNMENT,
            name=targets[0] if targets else None,
            location=self.extract_location(node),
            metadata={"targets": targets, "python_node": node}
        )
        
        # Normalize value
        assign_node.add_child(self.normalize(node.value))
        
        return assign_node
    
    def _normalize_module(self, node: ast.Module) -> UnifiedASTNode:
        """Normalize a module."""
        module_node = UnifiedASTNode(
            type=NodeType.MODULE,
            location=self.extract_location(node),
            metadata={"python_node": node}
        )
        
        for stmt in node.body:
            module_node.add_child(self.normalize(stmt))
        
        return module_node
    
    def _normalize_class(self, node: ast.ClassDef) -> UnifiedASTNode:
        """Normalize a class definition."""
        class_node = UnifiedASTNode(
            type=NodeType.CLASS,
            name=node.name,
            location=self.extract_location(node),
            docstring=ast.get_docstring(node),
            metadata={"python_node": node}
        )
        
        for stmt in node.body:
            class_node.add_child(self.normalize(stmt))
        
        return class_node
    
    def _normalize_return(self, node: ast.Return) -> UnifiedASTNode:
        """Normalize a return statement."""
        return_node = UnifiedASTNode(
            type=NodeType.RETURN,
            location=self.extract_location(node),
            metadata={"python_node": node}
        )
        
        if node.value:
            return_node.add_child(self.normalize(node.value))
        
        return return_node
    
    def _normalize_if(self, node: ast.If) -> UnifiedASTNode:
        """Normalize an if statement."""
        if_node = UnifiedASTNode(
            type=NodeType.IF,
            location=self.extract_location(node),
            metadata={"python_node": node}
        )
        
        # Normalize condition
        if_node.add_child(self.normalize(node.test))
        
        # Normalize body
        for stmt in node.body:
            if_node.add_child(self.normalize(stmt))
        
        # Normalize else
        for stmt in node.orelse:
            if_node.add_child(self.normalize(stmt))
        
        return if_node
    
    def _normalize_while(self, node: ast.While) -> UnifiedASTNode:
        """Normalize a while loop."""
        while_node = UnifiedASTNode(
            type=NodeType.WHILE,
            location=self.extract_location(node),
            metadata={"python_node": node}
        )
        
        # Normalize condition
        while_node.add_child(self.normalize(node.test))
        
        # Normalize body
        for stmt in node.body:
            while_node.add_child(self.normalize(stmt))
        
        return while_node
    
    def _normalize_for(self, node: ast.For) -> UnifiedASTNode:
        """Normalize a for loop."""
        for_node = UnifiedASTNode(
            type=NodeType.FOR,
            location=self.extract_location(node),
            metadata={"python_node": node}
        )
        
        # Normalize target and iter
        for_node.add_child(self.normalize(node.target))
        for_node.add_child(self.normalize(node.iter))
        
        # Normalize body
        for stmt in node.body:
            for_node.add_child(self.normalize(stmt))
        
        return for_node
    
    def _normalize_try(self, node: ast.Try) -> UnifiedASTNode:
        """Normalize a try statement."""
        try_node = UnifiedASTNode(
            type=NodeType.TRY,
            location=self.extract_location(node),
            metadata={"python_node": node}
        )
        
        # Normalize body
        for stmt in node.body:
            try_node.add_child(self.normalize(stmt))
        
        # Normalize handlers
        for handler in node.handlers:
            except_node = UnifiedASTNode(
                type=NodeType.EXCEPT,
                name=handler.type.id if isinstance(handler.type, ast.Name) else None,
                location=self.extract_location(handler)
            )
            for stmt in handler.body:
                except_node.add_child(self.normalize(stmt))
            try_node.add_child(except_node)
        
        # Normalize finally
        for stmt in node.finalbody:
            finally_node = UnifiedASTNode(
                type=NodeType.FINALLY,
                location=self.extract_location(node)
            )
            finally_node.add_child(self.normalize(stmt))
            try_node.add_child(finally_node)
        
        return try_node
    
    def _normalize_import(self, node: ast.Import | ast.ImportFrom) -> UnifiedASTNode:
        """Normalize an import statement."""
        names = []
        for alias in node.names:
            names.append(alias.name)
        
        return UnifiedASTNode(
            type=NodeType.IMPORT,
            name=", ".join(names),
            location=self.extract_location(node),
            metadata={"python_node": node, "names": names}
        )
    
    def _normalize_name(self, node: ast.Name) -> UnifiedASTNode:
        """Normalize a name (identifier)."""
        return UnifiedASTNode(
            type=NodeType.IDENTIFIER,
            name=node.id,
            location=self.extract_location(node),
            metadata={"python_node": node}
        )
    
    def _normalize_constant(self, node: ast.Constant) -> UnifiedASTNode:
        """Normalize a constant literal."""
        return UnifiedASTNode(
            type=NodeType.LITERAL,
            value=node.value,
            location=self.extract_location(node),
            metadata={"python_node": node}
        )
    
    def _normalize_binop(self, node: ast.BinOp) -> UnifiedASTNode:
        """Normalize a binary operation."""
        binop_node = UnifiedASTNode(
            type=NodeType.BINARY_OP,
            name=type(node.op).__name__,
            location=self.extract_location(node),
            metadata={"python_node": node}
        )
        
        binop_node.add_child(self.normalize(node.left))
        binop_node.add_child(self.normalize(node.right))
        
        return binop_node
    
    def _normalize_attribute(self, node: ast.Attribute) -> UnifiedASTNode:
        """Normalize an attribute access."""
        attr_node = UnifiedASTNode(
            type=NodeType.MEMBER_ACCESS,
            name=node.attr,
            location=self.extract_location(node),
            metadata={"python_node": node}
        )
        
        attr_node.add_child(self.normalize(node.value))
        
        return attr_node
    
    def _normalize_subscript(self, node: ast.Subscript) -> UnifiedASTNode:
        """Normalize a subscript operation."""
        subscript_node = UnifiedASTNode(
            type=NodeType.SUBSCRIPT,
            location=self.extract_location(node),
            metadata={"python_node": node}
        )
        
        subscript_node.add_child(self.normalize(node.value))
        subscript_node.add_child(self.normalize(node.slice))
        
        return subscript_node
    
    def _normalize_await(self, node: ast.Await) -> UnifiedASTNode:
        """Normalize an await expression."""
        await_node = UnifiedASTNode(
            type=NodeType.AWAIT,
            location=self.extract_location(node),
            metadata={"python_node": node}
        )
        
        await_node.add_child(self.normalize(node.value))
        
        return await_node
    
    def extract_location(self, node: ast.AST) -> Optional[SourceLocation]:
        """Extract source location from Python AST node."""
        if hasattr(node, 'lineno') and hasattr(node, 'col_offset'):
            end_line = getattr(node, 'end_lineno', node.lineno)
            end_col = getattr(node, 'end_col_offset', node.col_offset)
            return SourceLocation(
                line=node.lineno,
                column=node.col_offset,
                end_line=end_line,
                end_column=end_col
            )
        return None
