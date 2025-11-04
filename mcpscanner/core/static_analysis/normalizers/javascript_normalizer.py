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

"""JavaScript AST normalizer."""

from typing import Any, Optional

try:
    from tree_sitter import Node
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False
    Node = Any

from ..unified_ast import (
    ASTNormalizer,
    NodeType,
    SourceLocation,
    UnifiedASTNode,
)


class JavaScriptASTNormalizer(ASTNormalizer):
    """Normalizes JavaScript tree-sitter AST to unified format."""
    
    def __init__(self, parser):
        """Initialize normalizer with parser for text extraction.
        
        Args:
            parser: JavaScriptParser instance
        """
        self.parser = parser
    
    def normalize(self, native_ast: Node) -> UnifiedASTNode:
        """Convert JavaScript tree-sitter AST to unified format.
        
        Args:
            native_ast: Tree-sitter node
            
        Returns:
            Unified AST node
        """
        node_type = native_ast.type
        
        # Map tree-sitter node types to unified types
        if node_type == 'program':
            return self._normalize_program(native_ast)
        elif node_type in ['function_declaration', 'function', 'generator_function_declaration']:
            return self.normalize_function(native_ast)
        elif node_type == 'arrow_function':
            return self._normalize_arrow_function(native_ast)
        elif node_type == 'method_definition':
            return self._normalize_method(native_ast)
        elif node_type == 'class_declaration':
            return self._normalize_class(native_ast)
        elif node_type in ['variable_declaration', 'lexical_declaration']:
            return self._normalize_variable_declaration(native_ast)
        elif node_type == 'expression_statement':
            return self._normalize_expression_statement(native_ast)
        elif node_type == 'call_expression':
            return self.normalize_call(native_ast)
        elif node_type == 'return_statement':
            return self._normalize_return(native_ast)
        elif node_type == 'if_statement':
            return self._normalize_if(native_ast)
        elif node_type == 'while_statement':
            return self._normalize_while(native_ast)
        elif node_type == 'for_statement':
            return self._normalize_for(native_ast)
        elif node_type == 'for_in_statement':
            return self._normalize_for_in(native_ast)
        elif node_type == 'try_statement':
            return self._normalize_try(native_ast)
        elif node_type in ['import_statement', 'import_declaration']:
            return self._normalize_import(native_ast)
        elif node_type == 'export_statement':
            return self._normalize_export(native_ast)
        elif node_type == 'identifier':
            return self._normalize_identifier(native_ast)
        elif node_type in ['string', 'number', 'true', 'false', 'null', 'undefined']:
            return self._normalize_literal(native_ast)
        elif node_type == 'binary_expression':
            return self._normalize_binary_expression(native_ast)
        elif node_type == 'member_expression':
            return self._normalize_member_expression(native_ast)
        elif node_type == 'subscript_expression':
            return self._normalize_subscript(native_ast)
        elif node_type == 'await_expression':
            return self._normalize_await(native_ast)
        elif node_type == 'assignment_expression':
            return self.normalize_assignment(native_ast)
        elif node_type == 'object':
            return self._normalize_object_literal(native_ast)
        elif node_type == 'array':
            return self._normalize_array_literal(native_ast)
        else:
            # Generic fallback
            node = UnifiedASTNode(
                type=NodeType.UNKNOWN,
                metadata={"js_type": node_type},
                location=self.extract_location(native_ast)
            )
            # Normalize children
            for child in native_ast.named_children:
                node.add_child(self.normalize(child))
            return node
    
    def normalize_function(self, node: Node) -> UnifiedASTNode:
        """Normalize a function declaration."""
        name_node = node.child_by_field_name('name')
        name = self.parser.get_node_text(name_node) if name_node else None
        
        # Extract parameters
        params = self.parser.get_function_parameters(node)
        
        # Check if async
        is_async = self.parser.is_async_function(node)
        
        # Check if generator
        is_generator = node.type == 'generator_function_declaration'
        
        # Extract JSDoc
        jsdoc = self.parser.extract_jsdoc(node)
        
        # Extract rich context like Python does
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
        
        func_node = UnifiedASTNode(
            type=NodeType.ASYNC_FUNCTION if is_async else NodeType.FUNCTION,
            name=name,
            parameters=params,
            is_async=is_async,
            is_generator=is_generator,
            jsdoc=jsdoc,
            location=self.extract_location(node),
            metadata={
                "js_node": node,
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
        """Normalize an arrow function."""
        # Extract parameters
        params = self.parser.get_function_parameters(node)
        
        # Check if async
        is_async = self.parser.is_async_function(node)
        
        # Try to get name from parent assignment
        name = None
        parent = node.parent
        if parent and parent.type == 'variable_declarator':
            name_node = parent.child_by_field_name('name')
            if name_node:
                name = self.parser.get_node_text(name_node)
        
        # Extract rich context like Python does
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
        
        func_node = UnifiedASTNode(
            type=NodeType.ASYNC_FUNCTION if is_async else NodeType.FUNCTION,
            name=name,
            parameters=params,
            is_async=is_async,
            location=self.extract_location(node),
            metadata={
                "js_node": node,
                "is_arrow": True,
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
        """Normalize a method definition."""
        name_node = node.child_by_field_name('name')
        name = self.parser.get_node_text(name_node) if name_node else None
        
        # Extract parameters
        params = self.parser.get_function_parameters(node)
        
        # Check if async
        is_async = self.parser.is_async_function(node)
        
        # Extract JSDoc
        jsdoc = self.parser.extract_jsdoc(node)
        
        func_node = UnifiedASTNode(
            type=NodeType.ASYNC_FUNCTION if is_async else NodeType.FUNCTION,
            name=name,
            parameters=params,
            is_async=is_async,
            jsdoc=jsdoc,
            location=self.extract_location(node),
            metadata={"js_node": node, "is_method": True}
        )
        
        # Normalize body
        body = self.parser.get_function_body(node)
        if body:
            for stmt in body.named_children:
                func_node.add_child(self.normalize(stmt))
        
        return func_node
    
    def normalize_call(self, node: Node) -> UnifiedASTNode:
        """Normalize a function call."""
        func_name = self.parser.get_call_name(node)
        
        call_node = UnifiedASTNode(
            type=NodeType.CALL,
            name=func_name,
            location=self.extract_location(node),
            metadata={"js_node": node}
        )
        
        # Normalize arguments
        args = node.child_by_field_name('arguments')
        if args:
            for arg in args.named_children:
                call_node.add_child(self.normalize(arg))
        
        return call_node
    
    def normalize_assignment(self, node: Node) -> UnifiedASTNode:
        """Normalize an assignment expression."""
        left = node.child_by_field_name('left')
        right = node.child_by_field_name('right')
        
        target_name = self.parser.get_node_text(left) if left else None
        
        assign_node = UnifiedASTNode(
            type=NodeType.ASSIGNMENT,
            name=target_name,
            location=self.extract_location(node),
            metadata={"js_node": node}
        )
        
        if right:
            assign_node.add_child(self.normalize(right))
        
        return assign_node
    
    def _normalize_program(self, node: Node) -> UnifiedASTNode:
        """Normalize a program (module)."""
        module_node = UnifiedASTNode(
            type=NodeType.MODULE,
            location=self.extract_location(node),
            metadata={"js_node": node}
        )
        
        for child in node.named_children:
            module_node.add_child(self.normalize(child))
        
        return module_node
    
    def _normalize_class(self, node: Node) -> UnifiedASTNode:
        """Normalize a class declaration."""
        name_node = node.child_by_field_name('name')
        name = self.parser.get_node_text(name_node) if name_node else None
        
        class_node = UnifiedASTNode(
            type=NodeType.CLASS,
            name=name,
            location=self.extract_location(node),
            metadata={"js_node": node}
        )
        
        body = node.child_by_field_name('body')
        if body:
            for child in body.named_children:
                class_node.add_child(self.normalize(child))
        
        return class_node
    
    def _normalize_variable_declaration(self, node: Node) -> UnifiedASTNode:
        """Normalize a variable declaration (const, let, var)."""
        # Variable declarations can have multiple declarators
        for child in node.named_children:
            if child.type == 'variable_declarator':
                name_node = child.child_by_field_name('name')
                value_node = child.child_by_field_name('value')
                
                name = self.parser.get_node_text(name_node) if name_node else None
                
                assign_node = UnifiedASTNode(
                    type=NodeType.ASSIGNMENT,
                    name=name,
                    location=self.extract_location(child),
                    metadata={"js_node": child}
                )
                
                if value_node:
                    assign_node.add_child(self.normalize(value_node))
                
                return assign_node
        
        # Fallback
        return UnifiedASTNode(
            type=NodeType.UNKNOWN,
            metadata={"js_type": node.type},
            location=self.extract_location(node)
        )
    
    def _normalize_expression_statement(self, node: Node) -> UnifiedASTNode:
        """Normalize an expression statement."""
        # Just normalize the expression itself
        if node.named_child_count > 0:
            return self.normalize(node.named_children[0])
        return UnifiedASTNode(
            type=NodeType.UNKNOWN,
            location=self.extract_location(node)
        )
    
    def _normalize_return(self, node: Node) -> UnifiedASTNode:
        """Normalize a return statement."""
        return_node = UnifiedASTNode(
            type=NodeType.RETURN,
            location=self.extract_location(node),
            metadata={"js_node": node}
        )
        
        # Normalize return value
        for child in node.named_children:
            return_node.add_child(self.normalize(child))
        
        return return_node
    
    def _normalize_if(self, node: Node) -> UnifiedASTNode:
        """Normalize an if statement."""
        if_node = UnifiedASTNode(
            type=NodeType.IF,
            location=self.extract_location(node),
            metadata={"js_node": node}
        )
        
        # Normalize condition
        condition = node.child_by_field_name('condition')
        if condition:
            if_node.add_child(self.normalize(condition))
        
        # Normalize consequence
        consequence = node.child_by_field_name('consequence')
        if consequence:
            if_node.add_child(self.normalize(consequence))
        
        # Normalize alternative (else)
        alternative = node.child_by_field_name('alternative')
        if alternative:
            if_node.add_child(self.normalize(alternative))
        
        return if_node
    
    def _normalize_while(self, node: Node) -> UnifiedASTNode:
        """Normalize a while loop."""
        while_node = UnifiedASTNode(
            type=NodeType.WHILE,
            location=self.extract_location(node),
            metadata={"js_node": node}
        )
        
        # Normalize condition
        condition = node.child_by_field_name('condition')
        if condition:
            while_node.add_child(self.normalize(condition))
        
        # Normalize body
        body = node.child_by_field_name('body')
        if body:
            while_node.add_child(self.normalize(body))
        
        return while_node
    
    def _normalize_for(self, node: Node) -> UnifiedASTNode:
        """Normalize a for loop."""
        for_node = UnifiedASTNode(
            type=NodeType.FOR,
            location=self.extract_location(node),
            metadata={"js_node": node}
        )
        
        # Normalize init, condition, update
        for field in ['initializer', 'condition', 'increment']:
            child = node.child_by_field_name(field)
            if child:
                for_node.add_child(self.normalize(child))
        
        # Normalize body
        body = node.child_by_field_name('body')
        if body:
            for_node.add_child(self.normalize(body))
        
        return for_node
    
    def _normalize_for_in(self, node: Node) -> UnifiedASTNode:
        """Normalize a for...in loop."""
        for_node = UnifiedASTNode(
            type=NodeType.FOR,
            location=self.extract_location(node),
            metadata={"js_node": node, "for_in": True}
        )
        
        # Normalize left and right
        left = node.child_by_field_name('left')
        right = node.child_by_field_name('right')
        
        if left:
            for_node.add_child(self.normalize(left))
        if right:
            for_node.add_child(self.normalize(right))
        
        # Normalize body
        body = node.child_by_field_name('body')
        if body:
            for_node.add_child(self.normalize(body))
        
        return for_node
    
    def _normalize_try(self, node: Node) -> UnifiedASTNode:
        """Normalize a try statement."""
        try_node = UnifiedASTNode(
            type=NodeType.TRY,
            location=self.extract_location(node),
            metadata={"js_node": node}
        )
        
        # Normalize body
        body = node.child_by_field_name('body')
        if body:
            for stmt in body.named_children:
                try_node.add_child(self.normalize(stmt))
        
        # Normalize handler (catch)
        handler = node.child_by_field_name('handler')
        if handler:
            except_node = UnifiedASTNode(
                type=NodeType.EXCEPT,
                location=self.extract_location(handler)
            )
            handler_body = handler.child_by_field_name('body')
            if handler_body:
                for stmt in handler_body.named_children:
                    except_node.add_child(self.normalize(stmt))
            try_node.add_child(except_node)
        
        # Normalize finalizer
        finalizer = node.child_by_field_name('finalizer')
        if finalizer:
            finally_node = UnifiedASTNode(
                type=NodeType.FINALLY,
                location=self.extract_location(finalizer)
            )
            for stmt in finalizer.named_children:
                finally_node.add_child(self.normalize(stmt))
            try_node.add_child(finally_node)
        
        return try_node
    
    def _normalize_import(self, node: Node) -> UnifiedASTNode:
        """Normalize an import statement."""
        source = node.child_by_field_name('source')
        source_text = self.parser.get_node_text(source) if source else None
        
        return UnifiedASTNode(
            type=NodeType.IMPORT,
            name=source_text,
            location=self.extract_location(node),
            metadata={"js_node": node}
        )
    
    def _normalize_export(self, node: Node) -> UnifiedASTNode:
        """Normalize an export statement."""
        return UnifiedASTNode(
            type=NodeType.EXPORT,
            location=self.extract_location(node),
            metadata={"js_node": node}
        )
    
    def _normalize_identifier(self, node: Node) -> UnifiedASTNode:
        """Normalize an identifier."""
        return UnifiedASTNode(
            type=NodeType.IDENTIFIER,
            name=self.parser.get_node_text(node),
            location=self.extract_location(node),
            metadata={"js_node": node}
        )
    
    def _normalize_literal(self, node: Node) -> UnifiedASTNode:
        """Normalize a literal value."""
        text = self.parser.get_node_text(node)
        
        # Try to parse the value
        value = text
        if node.type == 'number':
            try:
                value = float(text) if '.' in text else int(text)
            except ValueError:
                pass
        elif node.type in ['true', 'false']:
            value = text == 'true'
        elif node.type == 'null':
            value = None
        elif node.type == 'string':
            # Remove quotes
            value = text[1:-1] if len(text) >= 2 else text
        
        return UnifiedASTNode(
            type=NodeType.LITERAL,
            value=value,
            location=self.extract_location(node),
            metadata={"js_node": node}
        )
    
    def _normalize_binary_expression(self, node: Node) -> UnifiedASTNode:
        """Normalize a binary expression."""
        operator = node.child_by_field_name('operator')
        op_text = self.parser.get_node_text(operator) if operator else None
        
        binop_node = UnifiedASTNode(
            type=NodeType.BINARY_OP,
            name=op_text,
            location=self.extract_location(node),
            metadata={"js_node": node}
        )
        
        left = node.child_by_field_name('left')
        right = node.child_by_field_name('right')
        
        if left:
            binop_node.add_child(self.normalize(left))
        if right:
            binop_node.add_child(self.normalize(right))
        
        return binop_node
    
    def _normalize_member_expression(self, node: Node) -> UnifiedASTNode:
        """Normalize a member expression (obj.prop)."""
        prop = node.child_by_field_name('property')
        prop_name = self.parser.get_node_text(prop) if prop else None
        
        member_node = UnifiedASTNode(
            type=NodeType.MEMBER_ACCESS,
            name=prop_name,
            location=self.extract_location(node),
            metadata={"js_node": node}
        )
        
        obj = node.child_by_field_name('object')
        if obj:
            member_node.add_child(self.normalize(obj))
        
        return member_node
    
    def _normalize_subscript(self, node: Node) -> UnifiedASTNode:
        """Normalize a subscript expression (obj[index])."""
        subscript_node = UnifiedASTNode(
            type=NodeType.SUBSCRIPT,
            location=self.extract_location(node),
            metadata={"js_node": node}
        )
        
        obj = node.child_by_field_name('object')
        index = node.child_by_field_name('index')
        
        if obj:
            subscript_node.add_child(self.normalize(obj))
        if index:
            subscript_node.add_child(self.normalize(index))
        
        return subscript_node
    
    def _normalize_await(self, node: Node) -> UnifiedASTNode:
        """Normalize an await expression."""
        await_node = UnifiedASTNode(
            type=NodeType.AWAIT,
            location=self.extract_location(node),
            metadata={"js_node": node}
        )
        
        # Normalize the awaited expression
        for child in node.named_children:
            await_node.add_child(self.normalize(child))
        
        return await_node
    
    def _normalize_object_literal(self, node: Node) -> UnifiedASTNode:
        """Normalize an object literal { key: value, ... }."""
        obj_node = UnifiedASTNode(
            type=NodeType.OBJECT_LITERAL,
            location=self.extract_location(node),
            metadata={"js_node": node}
        )
        
        # Normalize all properties
        for child in node.named_children:
            if child.type == 'pair':
                # key: value
                key_node = child.child_by_field_name('key')
                value_node = child.child_by_field_name('value')
                
                if key_node and value_node:
                    # Create a property node
                    prop_node = UnifiedASTNode(
                        type=NodeType.PROPERTY,
                        name=self.parser.get_node_text(key_node),
                        location=self.extract_location(child)
                    )
                    prop_node.add_child(self.normalize(value_node))
                    obj_node.add_child(prop_node)
            
            elif child.type == 'shorthand_property_identifier':
                # Shorthand: { message } means { message: message }
                prop_name = self.parser.get_node_text(child)
                prop_node = UnifiedASTNode(
                    type=NodeType.PROPERTY,
                    name=prop_name,
                    location=self.extract_location(child)
                )
                # Add an identifier node as the value
                id_node = UnifiedASTNode(
                    type=NodeType.IDENTIFIER,
                    name=prop_name,
                    location=self.extract_location(child)
                )
                prop_node.add_child(id_node)
                obj_node.add_child(prop_node)
            
            elif child.type == 'spread_element':
                # ...spread
                obj_node.add_child(self.normalize(child))
        
        return obj_node
    
    def _normalize_array_literal(self, node: Node) -> UnifiedASTNode:
        """Normalize an array literal [elem1, elem2, ...]."""
        array_node = UnifiedASTNode(
            type=NodeType.ARRAY_LITERAL,
            location=self.extract_location(node),
            metadata={"js_node": node}
        )
        
        # Normalize all elements
        for child in node.named_children:
            array_node.add_child(self.normalize(child))
        
        return array_node
    
    def extract_location(self, node: Node) -> SourceLocation:
        """Extract source location from a node."""
        return SourceLocation(
            line=node.start_point[0] + 1,
            column=node.start_point[1],
            end_line=node.end_point[0] + 1,
            end_column=node.end_point[1]
        )
    
    def _extract_string_literals(self, node: Node) -> list[str]:
        """Extract all string literals from a node and its children.
        
        This helps the LLM see URLs, file paths, and other string constants.
        
        Args:
            node: AST node to search
            
        Returns:
            List of string literal values
        """
        literals = []
        
        def walk_for_strings(n: Node):
            # Check if this node is a string
            if n.type in ['string', 'template_string']:
                text = self.parser.get_node_text(n)
                # Clean up quotes
                text = text.strip('"\'\'`')
                if text and len(text) > 1:
                    literals.append(text)
            
            # Recurse into children
            for child in n.children:
                walk_for_strings(child)
        
        walk_for_strings(node)
        return literals
    
    def _extract_all_calls(self, node: Node) -> list[dict]:
        """Extract ALL function calls with their arguments.
        
        Let the LLM decide what's dangerous - no hardcoded patterns!
        
        Returns:
            List of dicts with call details
        """
        all_calls = []
        
        def extract_call(n: Node):
            if n.type == 'call_expression':
                # Extract function name
                func_node = n.child_by_field_name('function')
                func_name = self.parser.get_node_text(func_node) if func_node else 'unknown'
                
                # Extract arguments (keep them concise)
                args_node = n.child_by_field_name('arguments')
                args = []
                if args_node:
                    for arg in args_node.named_children:
                        arg_text = self.parser.get_node_text(arg)
                        # Only include if reasonably short
                        if len(arg_text) < 150:
                            args.append(arg_text)
                        else:
                            args.append(f"<long_arg_{len(arg_text)}_chars>")
                
                all_calls.append({
                    'function': func_name,
                    'arguments': args,
                    'line': n.start_point[0] + 1
                })
            
            for child in n.children:
                extract_call(child)
        
        extract_call(node)
        return all_calls
    
    def _extract_imports(self, node: Node) -> list[str]:
        """Extract all import statements.
        
        Returns:
            List of import statements
        """
        imports = []
        
        def find_imports(n: Node):
            if n.type in ['import_statement', 'import_from_statement']:
                import_text = self.parser.get_node_text(n)
                if len(import_text) < 200:
                    imports.append(import_text)
            
            for child in n.children:
                find_imports(child)
        
        find_imports(node)
        return imports
    
    def _extract_assignments(self, node: Node) -> list[dict]:
        """Extract all variable assignments.
        
        Returns:
            List of assignment info
        """
        assignments = []
        
        def find_assignments(n: Node):
            if n.type in ['variable_declarator', 'assignment_expression']:
                # Extract variable name
                var_name = None
                value = None
                
                if n.type == 'variable_declarator':
                    name_node = n.child_by_field_name('name')
                    value_node = n.child_by_field_name('value')
                    if name_node:
                        var_name = self.parser.get_node_text(name_node)
                    if value_node:
                        value_text = self.parser.get_node_text(value_node)
                        value = value_text if len(value_text) < 100 else f"<long_value_{len(value_text)}_chars>"
                
                elif n.type == 'assignment_expression':
                    left_node = n.child_by_field_name('left')
                    right_node = n.child_by_field_name('right')
                    if left_node:
                        var_name = self.parser.get_node_text(left_node)
                    if right_node:
                        value_text = self.parser.get_node_text(right_node)
                        value = value_text if len(value_text) < 100 else f"<long_value_{len(value_text)}_chars>"
                
                if var_name:
                    assignments.append({
                        'variable': var_name,
                        'value': value or '<unknown>',
                        'line': n.start_point[0] + 1
                    })
            
            for child in n.children:
                find_assignments(child)
        
        find_assignments(node)
        return assignments
    
    def _extract_return_expressions(self, node: Node) -> list[str]:
        """Extract all return expressions.
        
        Returns:
            List of return expression strings
        """
        returns = []
        
        def find_returns(n: Node):
            if n.type == 'return_statement':
                # Get the return value
                for child in n.children:
                    if child.type != 'return':
                        return_text = self.parser.get_node_text(child)
                        if len(return_text) < 150:
                            returns.append(return_text)
                        else:
                            returns.append(f"<long_return_{len(return_text)}_chars>")
            
            for child in n.children:
                find_returns(child)
        
        find_returns(node)
        return returns
    
    def _extract_exception_handlers(self, node: Node) -> list[dict]:
        """Extract all try-catch blocks.
        
        Returns:
            List of exception handler info
        """
        handlers = []
        
        def find_handlers(n: Node):
            if n.type == 'try_statement':
                handler_info = {
                    'line': n.start_point[0] + 1,
                    'has_catch': False,
                    'has_finally': False,
                    'catch_param': None
                }
                
                for child in n.children:
                    if child.type == 'catch_clause':
                        handler_info['has_catch'] = True
                        # Try to get catch parameter
                        param_node = child.child_by_field_name('parameter')
                        if param_node:
                            handler_info['catch_param'] = self.parser.get_node_text(param_node)
                    elif child.type == 'finally_clause':
                        handler_info['has_finally'] = True
                
                handlers.append(handler_info)
            
            for child in n.children:
                find_handlers(child)
        
        find_handlers(node)
        return handlers
    
    def _extract_control_flow(self, node: Node) -> dict:
        """Extract control flow structure."""
        has_conditionals = False
        has_loops = False
        has_exception_handling = False
        
        def check_control_flow(n):
            nonlocal has_conditionals, has_loops, has_exception_handling
            if n.type in ['if_statement', 'switch_statement', 'ternary_expression']:
                has_conditionals = True
            elif n.type in ['for_statement', 'while_statement', 'do_statement', 'for_in_statement']:
                has_loops = True
            elif n.type == 'try_statement':
                has_exception_handling = True
            for child in n.children:
                check_control_flow(child)
        
        check_control_flow(node)
        return {
            'has_conditionals': has_conditionals,
            'has_loops': has_loops,
            'has_exception_handling': has_exception_handling
        }
    
    def _extract_env_var_access(self, node: Node) -> list[str]:
        """Extract environment variable accesses (process.env.X)."""
        env_vars = []
        
        def find_env_access(n):
            if n.type == 'member_expression':
                text = self.parser.get_node_text(n)
                if 'process.env' in text:
                    # Extract the env var name
                    parts = text.split('.')
                    if len(parts) >= 3:
                        env_vars.append(parts[-1])
            for child in n.children:
                find_env_access(child)
        
        find_env_access(node)
        return env_vars
    
    def _extract_attribute_access(self, node: Node) -> list[dict]:
        """Extract object attribute accesses (obj.attr)."""
        accesses = []
        
        def find_attr_access(n):
            if n.type == 'member_expression':
                obj_node = n.child_by_field_name('object')
                prop_node = n.child_by_field_name('property')
                if obj_node and prop_node:
                    obj_name = self.parser.get_node_text(obj_node)
                    prop_name = self.parser.get_node_text(prop_node)
                    accesses.append({
                        'object': obj_name,
                        'attribute': prop_name,
                        'line': n.start_point[0] + 1
                    })
            for child in n.children:
                find_attr_access(child)
        
        find_attr_access(node)
        return accesses
    
    def _extract_variable_dependencies(self, node: Node) -> dict:
        """Extract variable dependencies (what variables depend on what).
        
        Like Python's _analyze_variable_dependencies - for each assignment,
        track which variables are used in the value.
        
        Returns:
            Dict mapping variable names to list of variables they depend on
        """
        dependencies = {}
        
        def extract_identifiers(n: Node) -> list[str]:
            """Extract all identifier names from a node."""
            identifiers = []
            if n.type == 'identifier':
                identifiers.append(self.parser.get_node_text(n))
            for child in n.children:
                identifiers.extend(extract_identifiers(child))
            return identifiers
        
        def find_dependencies(n: Node):
            # Variable declarations: const x = y + z
            if n.type == 'variable_declarator':
                name_node = n.child_by_field_name('name')
                value_node = n.child_by_field_name('value')
                if name_node and value_node:
                    var_name = self.parser.get_node_text(name_node)
                    deps = extract_identifiers(value_node)
                    if deps:
                        dependencies[var_name] = deps
            
            # Assignment expressions: x = y + z
            elif n.type == 'assignment_expression':
                left_node = n.child_by_field_name('left')
                right_node = n.child_by_field_name('right')
                if left_node and right_node:
                    var_name = self.parser.get_node_text(left_node)
                    deps = extract_identifiers(right_node)
                    if deps:
                        dependencies[var_name] = deps
            
            for child in n.children:
                find_dependencies(child)
        
        find_dependencies(node)
        return dependencies
