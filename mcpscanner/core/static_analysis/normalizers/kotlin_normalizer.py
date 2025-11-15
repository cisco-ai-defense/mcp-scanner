"""Kotlin AST normalizer to unified AST."""

from typing import List, Optional
from tree_sitter import Node

from ..unified_ast import UnifiedASTNode, NodeType, SourceLocation


class KotlinASTNormalizer:
    """Normalizes Kotlin tree-sitter AST to unified AST."""
    
    def __init__(self, parser):
        """Initialize normalizer.
        
        Args:
            parser: KotlinParser instance
        """
        self.parser = parser
    
    def normalize_function(self, node: Node) -> UnifiedASTNode:
        """Normalize a Kotlin function/lambda to unified AST.
        
        Args:
            node: Function or lambda node
            
        Returns:
            Unified function node
        """
        if node.type == 'lambda_literal':
            return self._normalize_lambda(node)
        elif node.type == 'function_declaration':
            return self._normalize_function_declaration(node)
        else:
            # Fallback
            return UnifiedASTNode(
                type=NodeType.FUNCTION,
                name="<unknown>",
                parameters=[],
                location=self._get_location(node)
            )
    
    def _normalize_lambda(self, node: Node) -> UnifiedASTNode:
        """Normalize lambda expression.
        
        Args:
            node: Lambda literal node
            
        Returns:
            Unified function node
        """
        # Extract parameters from lambda
        params = []
        for child in node.children:
            if child.type == 'lambda_parameters':
                # Kotlin lambda parameters can be:
                # 1. variable_declaration (with type): request: CallToolRequest
                # 2. simple_identifier (without type): request
                for param_child in child.children:
                    if param_child.type == 'variable_declaration':
                        # Extract the identifier from variable_declaration
                        param_text = self.parser.get_node_text(param_child)
                        # Split by ':' to get just the parameter name
                        param_name = param_text.split(':')[0].strip()
                        params.append(param_name)
                    elif param_child.type == 'simple_identifier':
                        params.append(self.parser.get_node_text(param_child))
        
        # If no explicit parameters, Kotlin uses 'it' implicitly
        if not params:
            # Check if lambda uses 'it'
            lambda_text = self.parser.get_node_text(node)
            if 'it.' in lambda_text or ' it ' in lambda_text or lambda_text.endswith('it'):
                params = ['it']
        
        # Extract body - in Kotlin lambdas, statements are direct children
        body_children = []
        for child in node.children:
            if child.type == 'statements':
                body_children = self._normalize_block(child)
            elif child.type not in ['{', '}', 'lambda_parameters', '->']:
                # Direct statement children (property_declaration, call_expression, etc.)
                normalized = self._normalize_node(child)
                if normalized:
                    body_children.append(normalized)
        
        # Check if async (suspend lambda)
        is_async = False
        parent = node.parent
        while parent:
            parent_text = self.parser.get_node_text(parent)
            if 'suspend' in parent_text:
                is_async = True
                break
            parent = parent.parent
        
        # Extract rich context
        string_literals = self._extract_string_literals(node)
        all_calls = self._extract_all_calls(node)
        control_flow = self._extract_control_flow(node)
        env_var_access = self._extract_env_var_access(node)
        variable_dependencies = self._extract_variable_dependencies(node)
        
        return UnifiedASTNode(
            type=NodeType.FUNCTION,
            name="<lambda>",
            parameters=params,
            children=body_children,
            is_async=is_async,
            location=self._get_location(node),
            metadata={
                'string_literals': string_literals,
                'all_calls': all_calls,
                'control_flow': control_flow,
                'env_var_access': env_var_access,
                'variable_dependencies': variable_dependencies
            }
        )
    
    def _normalize_function_declaration(self, node: Node) -> UnifiedASTNode:
        """Normalize function declaration.
        
        Args:
            node: Function declaration node
            
        Returns:
            Unified function node
        """
        func_name = None
        params = []
        return_type = None
        is_async = False
        
        # Extract function name
        for child in node.children:
            if child.type == 'simple_identifier':
                func_name = self.parser.get_node_text(child)
                break
        
        # Extract parameters
        for child in node.children:
            if child.type == 'function_value_parameters':
                params = self._extract_parameters(child)
        
        # Check for suspend modifier
        for child in node.children:
            if child.type == 'modifiers':
                modifiers_text = self.parser.get_node_text(child)
                if 'suspend' in modifiers_text:
                    is_async = True
        
        # Extract body
        body_children = []
        for child in node.children:
            if child.type == 'function_body':
                for subchild in child.children:
                    if subchild.type == 'block':
                        body_children = self._normalize_block(subchild)
        
        return UnifiedASTNode(
            type=NodeType.FUNCTION,
            name=func_name or "<anonymous>",
            parameters=params,
            children=body_children,
            is_async=is_async,
            return_type=return_type,
            location=self._get_location(node)
        )
    
    def _extract_parameters(self, params_node: Node) -> List[str]:
        """Extract parameter names from function parameters.
        
        Args:
            params_node: Function parameters node
            
        Returns:
            List of parameter names
        """
        params = []
        for child in params_node.children:
            if child.type == 'parameter':
                for subchild in child.children:
                    if subchild.type == 'simple_identifier':
                        params.append(self.parser.get_node_text(subchild))
                        break
        return params
    
    def _normalize_block(self, node: Node) -> List[UnifiedASTNode]:
        """Normalize a block of statements.
        
        Args:
            node: Block or statements node
            
        Returns:
            List of unified nodes
        """
        children = []
        for child in node.children:
            if child.type not in ['{', '}', ';']:
                normalized = self._normalize_node(child)
                if normalized:
                    children.append(normalized)
        return children
    
    def _normalize_node(self, node: Node) -> Optional[UnifiedASTNode]:
        """Normalize any AST node.
        
        Args:
            node: AST node
            
        Returns:
            Unified AST node or None
        """
        if node.type == 'property_declaration':
            return self._normalize_variable_declaration(node)
        elif node.type == 'call_expression':
            return self._normalize_call(node)
        elif node.type == 'assignment':
            return self._normalize_assignment(node)
        elif node.type == 'return_expression':
            return self._normalize_return(node)
        elif node.type == 'if_expression':
            return self._normalize_if(node)
        elif node.type in ['string_literal', 'integer_literal', 'boolean_literal', 'null_literal']:
            return self._normalize_literal(node)
        elif node.type == 'simple_identifier':
            return UnifiedASTNode(
                type=NodeType.IDENTIFIER,
                name=self.parser.get_node_text(node),
                location=self._get_location(node)
            )
        elif node.type == 'binary_expression':
            return self._normalize_binary_op(node)
        elif node.type == 'navigation_expression':
            # Handle object.property access
            return self._normalize_navigation(node)
        elif node.type == 'as_expression':
            # Handle type casts - extract the value before 'as'
            for child in node.children:
                if child.type != 'as' and not child.type.endswith('_type'):
                    return self._normalize_node(child)
        elif node.type == 'indexing_expression':
            # Handle array/map access like arguments["username"]
            return self._normalize_indexing(node)
        else:
            # For other nodes, recursively process children
            children = []
            for child in node.children:
                normalized = self._normalize_node(child)
                if normalized:
                    children.append(normalized)
            
            if children:
                return UnifiedASTNode(
                    type=NodeType.STATEMENT,
                    children=children,
                    location=self._get_location(node)
                )
        
        return None
    
    def _normalize_variable_declaration(self, node: Node) -> UnifiedASTNode:
        """Normalize variable declaration (val/var).
        
        Args:
            node: Property declaration node
            
        Returns:
            Unified assignment node
        """
        var_name = None
        value_node = None
        
        for child in node.children:
            if child.type == 'variable_declaration':
                for subchild in child.children:
                    if subchild.type in ['simple_identifier', 'identifier']:
                        var_name = self.parser.get_node_text(subchild)
            elif child.type == 'as_expression':
                # Handle type casts: (value as Type)
                # Extract the value before 'as'
                for subchild in child.children:
                    if subchild.type != 'as' and not subchild.type.endswith('_type'):
                        value_node = subchild
                        break
            elif child.type not in ['val', 'var', '=', ':', 'type_reference']:
                if '=' in self.parser.get_node_text(node):
                    value_node = child
        
        value_child = self._normalize_node(value_node) if value_node else None
        
        return UnifiedASTNode(
            type=NodeType.ASSIGNMENT,
            name=var_name,
            children=[value_child] if value_child else [],
            location=self._get_location(node)
        )
    
    def _normalize_call(self, node: Node) -> UnifiedASTNode:
        """Normalize function/method call.
        
        Args:
            node: Call expression node
            
        Returns:
            Unified call node
        """
        # Extract method name and receiver object
        # Kotlin structure: simple_identifier . simple_identifier value_arguments
        # OR: navigation_expression value_arguments
        method_name = None
        receiver_node = None
        identifiers = []
        
        for child in node.children:
            if child.type == 'simple_identifier':
                identifiers.append(child)
            elif child.type == 'navigation_expression':
                # For chained calls like obj.method()
                nav_node = self._normalize_navigation(child)
                if nav_node:
                    receiver_node = nav_node
                    # Get the last identifier as method name
                    nav_text = self.parser.get_node_text(child)
                    if '.' in nav_text:
                        method_name = nav_text.split('.')[-1]
            elif child.type == 'call_expression':
                # Nested call
                receiver_node = self._normalize_call(child)
        
        # If we have multiple identifiers, first is receiver, last is method name
        if len(identifiers) >= 2:
            receiver_node = UnifiedASTNode(
                type=NodeType.IDENTIFIER,
                name=self.parser.get_node_text(identifiers[0]),
                location=self._get_location(identifiers[0])
            )
            method_name = self.parser.get_node_text(identifiers[-1])
        elif len(identifiers) == 1:
            method_name = self.parser.get_node_text(identifiers[0])
        
        if not method_name:
            method_name = self.parser.get_node_text(node)
        
        # Extract arguments
        args = []
        if receiver_node:
            # Add the receiver as the first child
            args.append(receiver_node)
        
        for child in node.children:
            if child.type == 'value_arguments':
                for arg_child in child.children:
                    if arg_child.type == 'value_argument':
                        for subchild in arg_child.children:
                            normalized_arg = self._normalize_node(subchild)
                            if normalized_arg:
                                args.append(normalized_arg)
        
        return UnifiedASTNode(
            type=NodeType.CALL,
            name=method_name,
            children=args,
            location=self._get_location(node)
        )
    
    def _normalize_indexing(self, node: Node) -> UnifiedASTNode:
        """Normalize indexing expression (array[index] or map["key"]).
        
        Args:
            node: Indexing expression node
            
        Returns:
            Unified subscript node
        """
        # Extract the object being indexed and the index
        obj_node = None
        index_node = None
        
        for child in node.children:
            if child.type == '[':
                continue
            elif child.type == ']':
                break
            elif obj_node is None:
                obj_node = self._normalize_node(child)
            else:
                index_node = self._normalize_node(child)
        
        children = []
        if obj_node:
            children.append(obj_node)
        if index_node:
            children.append(index_node)
        
        return UnifiedASTNode(
            type=NodeType.SUBSCRIPT,
            name=self.parser.get_node_text(node),
            children=children,
            location=self._get_location(node)
        )
    
    def _normalize_navigation(self, node: Node) -> UnifiedASTNode:
        """Normalize navigation expression (object.property).
        
        Args:
            node: Navigation expression node
            
        Returns:
            Unified member access node
        """
        # For navigation like request.params.arguments, we need to extract
        # the base identifier (request) for dataflow tracking
        
        # Try to find the leftmost identifier
        base_identifier = None
        
        def find_base_identifier(n):
            if n.type in ['simple_identifier', 'identifier']:
                return self.parser.get_node_text(n)
            # Recursively check children (leftmost first)
            for child in n.children:
                result = find_base_identifier(child)
                if result:
                    return result
            return None
        
        base_name = find_base_identifier(node)
        
        if base_name:
            # Create an identifier node for the base
            base = UnifiedASTNode(
                type=NodeType.IDENTIFIER,
                name=base_name,
                location=self._get_location(node)
            )
            # Return a member access with the base as a child
            return UnifiedASTNode(
                type=NodeType.MEMBER_ACCESS,
                name=self.parser.get_node_text(node),
                children=[base],
                location=self._get_location(node)
            )
        
        # Fallback
        return UnifiedASTNode(
            type=NodeType.IDENTIFIER,
            name=self.parser.get_node_text(node),
            location=self._get_location(node)
        )
    
    def _normalize_assignment(self, node: Node) -> UnifiedASTNode:
        """Normalize assignment expression.
        
        Args:
            node: Assignment node
            
        Returns:
            Unified assignment node
        """
        var_name = None
        value_node = None
        
        children = list(node.children)
        if len(children) >= 3:
            # Pattern: identifier = value
            if children[0].type == 'simple_identifier':
                var_name = self.parser.get_node_text(children[0])
            value_node = children[-1]
        
        value_child = self._normalize_node(value_node) if value_node else None
        
        return UnifiedASTNode(
            type=NodeType.ASSIGNMENT,
            name=var_name,
            children=[value_child] if value_child else [],
            location=self._get_location(node)
        )
    
    def _normalize_return(self, node: Node) -> UnifiedASTNode:
        """Normalize return statement.
        
        Args:
            node: Return node
            
        Returns:
            Unified return node
        """
        return_value = None
        for child in node.children:
            if child.type != 'return':
                return_value = self._normalize_node(child)
                break
        
        return UnifiedASTNode(
            type=NodeType.RETURN,
            children=[return_value] if return_value else [],
            location=self._get_location(node)
        )
    
    def _normalize_if(self, node: Node) -> UnifiedASTNode:
        """Normalize if expression.
        
        Args:
            node: If node
            
        Returns:
            Unified if node
        """
        condition = None
        then_branch = None
        else_branch = None
        
        for child in node.children:
            if child.type == 'control_structure_body':
                if then_branch is None:
                    then_branch = self._normalize_node(child)
                else:
                    else_branch = self._normalize_node(child)
            elif child.type not in ['if', 'else', '(', ')']:
                if condition is None:
                    condition = self._normalize_node(child)
        
        children = [condition] if condition else []
        if then_branch:
            children.append(then_branch)
        if else_branch:
            children.append(else_branch)
        
        return UnifiedASTNode(
            type=NodeType.IF,
            children=children,
            location=self._get_location(node)
        )
    
    def _normalize_literal(self, node: Node) -> UnifiedASTNode:
        """Normalize literal value.
        
        Args:
            node: Literal node
            
        Returns:
            Unified literal node
        """
        return UnifiedASTNode(
            type=NodeType.LITERAL,
            name=self.parser.get_node_text(node),
            location=self._get_location(node)
        )
    
    def _normalize_binary_op(self, node: Node) -> UnifiedASTNode:
        """Normalize binary operation.
        
        Args:
            node: Binary expression node
            
        Returns:
            Unified binary op node
        """
        children = []
        op = None
        
        for child in node.children:
            if child.type in ['+', '-', '*', '/', '%', '==', '!=', '<', '>', '<=', '>=', '&&', '||']:
                op = self.parser.get_node_text(child)
            else:
                normalized = self._normalize_node(child)
                if normalized:
                    children.append(normalized)
        
        return UnifiedASTNode(
            type=NodeType.BINARY_OP,
            name=op,
            children=children,
            location=self._get_location(node)
        )
    
    def _get_location(self, node: Node) -> SourceLocation:
        """Extract location from node.
        
        Args:
            node: AST node
            
        Returns:
            SourceLocation object
        """
        return SourceLocation(
            line=node.start_point[0] + 1,
            column=node.start_point[1],
            end_line=node.end_point[0] + 1,
            end_column=node.end_point[1]
        )
    
    def _extract_string_literals(self, node: Node) -> List[str]:
        """Extract all string literals."""
        literals = []
        def walk(n):
            if n.type in ['string_literal', 'line_string_literal']:
                text = self.parser.get_node_text(n).strip('"')
                if text and len(text) > 1:
                    literals.append(text)
            for child in n.children:
                walk(child)
        walk(node)
        return literals
    
    def _extract_all_calls(self, node: Node) -> List[dict]:
        """Extract all function calls."""
        calls = []
        def walk(n):
            if n.type == 'call_expression':
                func_name = None
                args = []
                for child in n.children:
                    if child.type in ['simple_identifier', 'navigation_expression']:
                        func_name = self.parser.get_node_text(child)
                    elif child.type == 'call_suffix':
                        for arg in child.children:
                            if arg.type == 'value_arguments':
                                for va in arg.children:
                                    if va.type == 'value_argument':
                                        arg_text = self.parser.get_node_text(va)
                                        args.append(arg_text if len(arg_text) < 150 else f"<long_{len(arg_text)}>")
                if func_name:
                    calls.append({'function': func_name, 'arguments': args, 'line': n.start_point[0] + 1})
            for child in n.children:
                walk(child)
        walk(node)
        return calls
    
    def _extract_control_flow(self, node: Node) -> dict:
        """Extract control flow structure."""
        has_conditionals = False
        has_loops = False
        has_exception_handling = False
        
        def check(n):
            nonlocal has_conditionals, has_loops, has_exception_handling
            if n.type in ['if_expression', 'when_expression']:
                has_conditionals = True
            elif n.type in ['for_statement', 'while_statement', 'do_while_statement']:
                has_loops = True
            elif n.type == 'try_expression':
                has_exception_handling = True
            for child in n.children:
                check(child)
        
        check(node)
        return {
            'has_conditionals': has_conditionals,
            'has_loops': has_loops,
            'has_exception_handling': has_exception_handling
        }
    
    def _extract_env_var_access(self, node: Node) -> list[str]:
        """Extract environment variable accesses (System.getenv)."""
        env_vars = []
        
        def find_env(n):
            if n.type == 'call_expression':
                text = self.parser.get_node_text(n)
                if 'System.getenv' in text or 'getenv' in text:
                    for child in n.children:
                        if child.type == 'call_suffix':
                            for cs in child.children:
                                if cs.type == 'value_arguments':
                                    for va in cs.children:
                                        if va.type == 'value_argument':
                                            arg_text = self.parser.get_node_text(va)
                                            if arg_text.startswith('"'):
                                                var_name = arg_text.strip('"')
                                                if var_name:
                                                    env_vars.append(var_name)
            for child in n.children:
                find_env(child)
        
        find_env(node)
        return env_vars
    
    def _extract_variable_dependencies(self, node: Node) -> dict:
        """Extract variable dependencies."""
        dependencies = {}
        
        def extract_identifiers(n: Node) -> list[str]:
            identifiers = []
            if n.type == 'simple_identifier':
                identifiers.append(self.parser.get_node_text(n))
            for child in n.children:
                identifiers.extend(extract_identifiers(child))
            return identifiers
        
        def find_deps(n: Node):
            if n.type == 'property_declaration':
                var_name = None
                deps = []
                for child in n.children:
                    if child.type == 'variable_declaration':
                        for vc in child.children:
                            if vc.type == 'simple_identifier':
                                var_name = self.parser.get_node_text(vc)
                    elif child.type not in ['val', 'var', '=', ':']:
                        deps = extract_identifiers(child)
                if var_name and deps:
                    dependencies[var_name] = deps
            for child in n.children:
                find_deps(child)
        
        find_deps(node)
        return dependencies
