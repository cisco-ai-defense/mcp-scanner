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

"""TypeScript AST normalizer."""

from typing import Any

try:
    from tree_sitter import Node
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False
    Node = Any

from ..unified_ast import NodeType, UnifiedASTNode
from .javascript_normalizer import JavaScriptASTNormalizer


class TypeScriptASTNormalizer(JavaScriptASTNormalizer):
    """Normalizes TypeScript tree-sitter AST to unified format.
    
    Extends JavaScriptASTNormalizer since TypeScript is a superset of JavaScript.
    """
    
    def normalize_function(self, node: Node) -> UnifiedASTNode:
        """Normalize a function declaration with TypeScript types."""
        name_node = node.child_by_field_name('name')
        name = self.parser.get_node_text(name_node) if name_node else None
        
        # Extract parameters with types
        params_with_types = self.parser.get_function_parameters_with_types(node)
        params = [p.get('name', f'param{i}') for i, p in enumerate(params_with_types)]
        
        # Check if async
        is_async = self.parser.is_async_function(node)
        
        # Check if generator
        is_generator = node.type == 'generator_function_declaration'
        
        # Extract TSDoc
        tsdoc = self.parser.extract_tsdoc(node)
        
        # Extract return type
        return_type = self.parser.get_function_return_type(node)
        
        # Extract decorators
        decorators = []
        for dec in self.parser.find_decorators(node):
            decorators.append(self.parser.get_node_text(dec))
        
        # Extract rich context
        string_literals = self._extract_string_literals(node)
        all_calls = self._extract_all_calls(node)
        imports = self._extract_imports(node)
        assignments = self._extract_assignments(node)
        return_expressions = self._extract_return_expressions(node)
        exception_handlers = self._extract_exception_handlers(node)
        control_flow = self._extract_control_flow(node)
        env_var_access = self._extract_env_var_access(node)
        attribute_access = self._extract_attribute_access(node)
        variable_dependencies = self._extract_variable_dependencies(node)
        parameter_flows = self._extract_parameter_flows(node, params)
        
        func_node = UnifiedASTNode(
            type=NodeType.ASYNC_FUNCTION if is_async else NodeType.FUNCTION,
            name=name,
            parameters=params,
            return_type=return_type,
            is_async=is_async,
            is_generator=is_generator,
            decorators=decorators,
            jsdoc=tsdoc,  # Store TSDoc in jsdoc field
            location=self.extract_location(node),
            metadata={
                "ts_node": node,
                "params_with_types": params_with_types,
                "string_literals": string_literals,
                "all_calls": all_calls,
                "imports": imports,
                "assignments": assignments,
                "return_expressions": return_expressions,
                "exception_handlers": exception_handlers,
                "control_flow": control_flow,
                "env_var_access": env_var_access,
                "attribute_access": attribute_access,
                "variable_dependencies": variable_dependencies
            }
        )
        
        # Normalize body
        body = self.parser.get_function_body(node)
        if body:
            if body.type == 'statement_block':
                for stmt in body.named_children:
                    func_node.add_child(self.normalize(stmt))
            else:
                # Arrow function with expression body
                func_node.add_child(self.normalize(body))
        
        return func_node
    
    def _normalize_arrow_function(self, node: Node) -> UnifiedASTNode:
        """Normalize an arrow function with TypeScript types."""
        # Extract parameters with types
        params_with_types = self.parser.get_function_parameters_with_types(node)
        params = [p.get('name', f'param{i}') for i, p in enumerate(params_with_types)]
        
        # Check if async
        is_async = self.parser.is_async_function(node)
        
        # Extract return type
        return_type = self.parser.get_function_return_type(node)
        
        # Try to get name from parent assignment
        name = None
        parent = node.parent
        if parent and parent.type == 'variable_declarator':
            name_node = parent.child_by_field_name('name')
            if name_node:
                name = self.parser.get_node_text(name_node)
        
        # Extract rich context (inherits from JavaScript)
        string_literals = self._extract_string_literals(node)
        all_calls = self._extract_all_calls(node)
        imports = self._extract_imports(node)
        assignments = self._extract_assignments(node)
        return_expressions = self._extract_return_expressions(node)
        exception_handlers = self._extract_exception_handlers(node)
        control_flow = self._extract_control_flow(node)
        env_var_access = self._extract_env_var_access(node)
        attribute_access = self._extract_attribute_access(node)
        variable_dependencies = self._extract_variable_dependencies(node)
        parameter_flows = self._extract_parameter_flows(node, params)
        
        func_node = UnifiedASTNode(
            type=NodeType.ASYNC_FUNCTION if is_async else NodeType.FUNCTION,
            name=name,
            parameters=params,
            return_type=return_type,
            is_async=is_async,
            location=self.extract_location(node),
            metadata={
                "ts_node": node,
                "is_arrow": True,
                "params_with_types": params_with_types,
                "string_literals": string_literals,
                "all_calls": all_calls,
                "imports": imports,
                "assignments": assignments,
                "return_expressions": return_expressions,
                "exception_handlers": exception_handlers,
                "control_flow": control_flow,
                "env_var_access": env_var_access,
                "attribute_access": attribute_access,
                "variable_dependencies": variable_dependencies
            }
        )
        
        # Normalize body
        body = self.parser.get_function_body(node)
        if body:
            if body.type == 'statement_block':
                for stmt in body.named_children:
                    func_node.add_child(self.normalize(stmt))
            else:
                # Expression body - wrap in implicit return
                return_node = UnifiedASTNode(
                    type=NodeType.RETURN,
                    location=self.extract_location(body)
                )
                return_node.add_child(self.normalize(body))
                func_node.add_child(return_node)
        
        return func_node
    
    def _normalize_method(self, node: Node) -> UnifiedASTNode:
        """Normalize a method definition with TypeScript types."""
        name_node = node.child_by_field_name('name')
        name = self.parser.get_node_text(name_node) if name_node else None
        
        # Extract parameters with types
        params_with_types = self.parser.get_function_parameters_with_types(node)
        params = [p.get('name', f'param{i}') for i, p in enumerate(params_with_types)]
        
        # Check if async
        is_async = self.parser.is_async_function(node)
        
        # Extract TSDoc
        tsdoc = self.parser.extract_tsdoc(node)
        
        # Extract return type
        return_type = self.parser.get_function_return_type(node)
        
        # Extract decorators
        decorators = []
        for dec in self.parser.find_decorators(node):
            decorators.append(self.parser.get_node_text(dec))
        
        # Extract rich context (inherits from JavaScript)
        string_literals = self._extract_string_literals(node)
        all_calls = self._extract_all_calls(node)
        imports = self._extract_imports(node)
        assignments = self._extract_assignments(node)
        return_expressions = self._extract_return_expressions(node)
        exception_handlers = self._extract_exception_handlers(node)
        control_flow = self._extract_control_flow(node)
        env_var_access = self._extract_env_var_access(node)
        attribute_access = self._extract_attribute_access(node)
        variable_dependencies = self._extract_variable_dependencies(node)
        parameter_flows = self._extract_parameter_flows(node, params)
        
        func_node = UnifiedASTNode(
            type=NodeType.ASYNC_FUNCTION if is_async else NodeType.FUNCTION,
            name=name,
            parameters=params,
            return_type=return_type,
            is_async=is_async,
            decorators=decorators,
            jsdoc=tsdoc,
            location=self.extract_location(node),
            metadata={
                "ts_node": node,
                "is_method": True,
                "params_with_types": params_with_types,
                "string_literals": string_literals,
                "all_calls": all_calls,
                "imports": imports,
                "assignments": assignments,
                "return_expressions": return_expressions,
                "exception_handlers": exception_handlers,
                "control_flow": control_flow,
                "env_var_access": env_var_access,
                "attribute_access": attribute_access,
                "variable_dependencies": variable_dependencies
            }
        )
        
        # Normalize body
        body = self.parser.get_function_body(node)
        if body:
            for stmt in body.named_children:
                func_node.add_child(self.normalize(stmt))
        
        return func_node
    
    def normalize_assignment(self, node: Node) -> UnifiedASTNode:
        """Normalize an assignment with type annotations."""
        left = node.child_by_field_name('left')
        right = node.child_by_field_name('right')
        
        target_name = self.parser.get_node_text(left) if left else None
        
        # Extract type annotation if present
        type_annotation = None
        if left:
            type_annotation = self.parser.get_type_annotation(left)
        
        assign_node = UnifiedASTNode(
            type=NodeType.ASSIGNMENT,
            name=target_name,
            location=self.extract_location(node),
            metadata={
                "ts_node": node,
                "type_annotation": type_annotation,
            }
        )
        
        if right:
            assign_node.add_child(self.normalize(right))
        
        return assign_node
