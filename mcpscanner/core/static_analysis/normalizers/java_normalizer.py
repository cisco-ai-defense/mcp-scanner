"""Java AST normalizer to unified AST."""

from typing import List, Optional
from tree_sitter import Node

from ..unified_ast import UnifiedASTNode, NodeType, SourceLocation


class JavaASTNormalizer:
    """Normalizes Java tree-sitter AST to unified AST."""
    
    def __init__(self, parser):
        """Initialize normalizer.
        
        Args:
            parser: JavaParser instance
        """
        self.parser = parser
    
    def normalize_function(self, node: Node) -> UnifiedASTNode:
        """Normalize a Java method to unified function node.
        
        Args:
            node: Method declaration or lambda expression node
            
        Returns:
            Unified AST function node
        """
        if node.type == 'method_declaration':
            return self._normalize_method(node)
        elif node.type == 'lambda_expression':
            return self._normalize_lambda(node)
        else:
            raise ValueError(f"Unsupported function node type: {node.type}")
    
    def _normalize_method(self, node: Node) -> UnifiedASTNode:
        """Normalize method declaration.
        
        Args:
            node: Method declaration node
            
        Returns:
            Unified function node
        """
        # Extract method name
        method_name = None
        for child in node.children:
            if child.type == 'identifier':
                method_name = self.parser.get_node_text(child)
                break
        
        # Extract parameters
        parameters = []
        param_node = self._find_child_by_type(node, 'formal_parameters')
        if param_node:
            parameters = self._extract_parameters(param_node)
        
        # Extract method body
        body_node = self._find_child_by_type(node, 'block')
        body_children = []
        if body_node:
            body_children = self._normalize_block(body_node)
        
        # Check if async (has CompletableFuture, Mono, Flux return type)
        is_async = self._is_async_method(node)
        
        # Extract Javadoc
        javadoc = self.parser.extract_javadoc(node)
        
        # Extract rich context like Python does
        string_literals = self._extract_string_literals(node)
        all_calls = self._extract_all_calls(node)
        imports = self._extract_imports(node)
        assignments = self._extract_assignments(node)
        return_expressions = self._extract_return_expressions(node)
        exception_handlers = self._extract_exception_handlers(node)
        control_flow = self._extract_control_flow(node)
        env_var_access = self._extract_env_var_access(node)
        variable_dependencies = self._extract_variable_dependencies(node)
        
        return UnifiedASTNode(
            type=NodeType.FUNCTION,
            name=method_name or "<anonymous>",
            children=body_children,
            parameters=parameters,
            is_async=is_async,
            jsdoc=javadoc,
            location=self._get_location(node),
            metadata={
                'string_literals': string_literals,
                'all_calls': all_calls,
                'imports': imports,
                'assignments': assignments,
                'return_expressions': return_expressions,
                'exception_handlers': exception_handlers,
                'control_flow': control_flow,
                'env_var_access': env_var_access,
                'variable_dependencies': variable_dependencies
            }
        )
    
    def _normalize_lambda(self, node: Node) -> UnifiedASTNode:
        """Normalize lambda expression.
        
        Args:
            node: Lambda expression node
            
        Returns:
            Unified function node
        """
        # Extract parameters
        parameters = []
        for child in node.children:
            if child.type == 'identifier':
                # Single parameter lambda: x -> x + 1
                parameters.append(self.parser.get_node_text(child))
            elif child.type == 'formal_parameters' or child.type == 'inferred_parameters':
                # Multiple parameters: (x, y) -> x + y
                parameters = self._extract_parameters(child)
        
        # Extract body
        body_children = []
        for child in node.children:
            if child.type == 'block':
                body_children = self._normalize_block(child)
            elif child.type not in ['identifier', 'formal_parameters', 'inferred_parameters', '->']:
                # Expression body: x -> x + 1
                body_children = [self._normalize_node(child)]
        
        return UnifiedASTNode(
            type=NodeType.FUNCTION,
            name="<lambda>",
            children=body_children,
            parameters=parameters,
            is_async=False,
            location=self._get_location(node)
        )
    
    def _extract_parameters(self, param_node: Node) -> List[str]:
        """Extract parameter names from formal_parameters node.
        
        Args:
            param_node: Formal parameters node
            
        Returns:
            List of parameter names
        """
        parameters = []
        
        for child in param_node.children:
            if child.type == 'formal_parameter':
                # Extract parameter name
                for subchild in child.children:
                    if subchild.type == 'identifier':
                        parameters.append(self.parser.get_node_text(subchild))
            elif child.type == 'identifier':
                # Inferred parameters
                parameters.append(self.parser.get_node_text(child))
        
        return parameters
    
    def _normalize_block(self, block_node: Node) -> List[UnifiedASTNode]:
        """Normalize a block of statements.
        
        Args:
            block_node: Block node
            
        Returns:
            List of normalized statement nodes
        """
        statements = []
        
        for child in block_node.children:
            if child.type not in ['{', '}']:
                normalized = self._normalize_node(child)
                if normalized:
                    statements.append(normalized)
        
        return statements
    
    def _normalize_node(self, node: Node) -> Optional[UnifiedASTNode]:
        """Normalize any AST node.
        
        Args:
            node: AST node
            
        Returns:
            Unified AST node or None
        """
        if node.type == 'local_variable_declaration':
            return self._normalize_variable_declaration(node)
        elif node.type == 'expression_statement':
            # Unwrap expression statement
            for child in node.children:
                if child.type != ';':
                    return self._normalize_node(child)
        elif node.type == 'method_invocation':
            return self._normalize_call(node)
        elif node.type == 'assignment_expression':
            return self._normalize_assignment(node)
        elif node.type == 'return_statement':
            return self._normalize_return(node)
        elif node.type == 'if_statement':
            return self._normalize_if(node)
        elif node.type in ['string_literal', 'decimal_integer_literal', 'true', 'false', 'null_literal']:
            return self._normalize_literal(node)
        elif node.type == 'identifier':
            return UnifiedASTNode(
                type=NodeType.IDENTIFIER,
                name=self.parser.get_node_text(node),
                location=self._get_location(node)
            )
        elif node.type == 'binary_expression':
            return self._normalize_binary_op(node)
        elif node.type == 'cast_expression':
            # Handle (Type) value - unwrap to get the value
            for child in node.children:
                if child.type not in ['(', ')', 'type_identifier', 'generic_type']:
                    return self._normalize_node(child)
        elif node.type == 'field_access':
            # Handle object.field access
            return self._normalize_field_access(node)
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
        """Normalize variable declaration.
        
        Args:
            node: Variable declaration node
            
        Returns:
            Unified assignment node
        """
        var_name = None
        value_node = None
        
        for child in node.children:
            if child.type == 'variable_declarator':
                for subchild in child.children:
                    if subchild.type == 'identifier':
                        var_name = self.parser.get_node_text(subchild)
                    elif subchild.type not in ['=']:
                        value_node = subchild
        
        value_child = self._normalize_node(value_node) if value_node else None
        
        return UnifiedASTNode(
            type=NodeType.ASSIGNMENT,
            name=var_name,
            children=[value_child] if value_child else [],
            location=self._get_location(node)
        )
    
    def _normalize_call(self, node: Node) -> UnifiedASTNode:
        """Normalize method invocation.
        
        Args:
            node: Method invocation node
            
        Returns:
            Unified call node
        """
        # Extract method name and receiver object
        # Tree-sitter structure: identifier . identifier argument_list
        # OR: method_invocation . identifier argument_list
        method_name = None
        receiver_node = None
        identifiers = []
        
        for child in node.children:
            if child.type == 'identifier':
                identifiers.append(child)
            elif child.type == 'field_access':
                # For chained calls
                field_text = self.parser.get_node_text(child)
                method_name = field_text
                receiver_node = self._extract_base_identifier(child)
            elif child.type == 'method_invocation':
                # Nested method call (e.g., Runtime.getRuntime().exec())
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
            if child.type == 'argument_list':
                for arg_child in child.children:
                    if arg_child.type not in ['(', ')', ',']:
                        normalized_arg = self._normalize_node(arg_child)
                        if normalized_arg:
                            args.append(normalized_arg)
        
        return UnifiedASTNode(
            type=NodeType.CALL,
            name=method_name,
            children=args,
            location=self._get_location(node)
        )
    
    def _extract_base_identifier(self, field_access_node: Node) -> Optional[UnifiedASTNode]:
        """Extract the base identifier from a field access chain.
        
        For example, from 'arguments.get' extract 'arguments'.
        
        Args:
            field_access_node: Field access node
            
        Returns:
            Identifier node for the base object
        """
        # Walk down the field access chain to find the base identifier
        current = field_access_node
        while current:
            for child in current.children:
                if child.type == 'identifier':
                    # This is the base identifier
                    return UnifiedASTNode(
                        type=NodeType.IDENTIFIER,
                        name=self.parser.get_node_text(child),
                        location=self._get_location(child)
                    )
                elif child.type == 'field_access':
                    # Nested field access, keep going
                    current = child
                    break
            else:
                break
        return None
    
    def _normalize_field_access(self, node: Node) -> UnifiedASTNode:
        """Normalize field access (object.field).
        
        Args:
            node: Field access node
            
        Returns:
            Unified member access node
        """
        # Extract object and field
        object_part = None
        field_name = None
        
        for child in node.children:
            if child.type == 'identifier':
                if object_part is None:
                    object_part = self._normalize_node(child)
                else:
                    field_name = self.parser.get_node_text(child)
            elif child.type == 'field_access':
                # Nested field access
                object_part = self._normalize_field_access(child)
            elif child.type not in ['.']:
                # Could be another expression
                if object_part is None:
                    object_part = self._normalize_node(child)
        
        return UnifiedASTNode(
            type=NodeType.MEMBER_ACCESS,
            name=field_name or self.parser.get_node_text(node),
            children=[object_part] if object_part else [],
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
        
        children_list = list(node.children)
        if len(children_list) >= 3:
            var_name = self.parser.get_node_text(children_list[0])
            value_node = children_list[2]  # After '='
        
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
            node: Return statement node
            
        Returns:
            Unified return node
        """
        return_value = None
        for child in node.children:
            if child.type not in ['return', ';']:
                return_value = self._normalize_node(child)
        
        return UnifiedASTNode(
            type=NodeType.RETURN,
            children=[return_value] if return_value else [],
            location=self._get_location(node)
        )
    
    def _normalize_if(self, node: Node) -> UnifiedASTNode:
        """Normalize if statement.
        
        Args:
            node: If statement node
            
        Returns:
            Unified conditional node
        """
        condition = None
        then_branch = None
        else_branch = None
        
        for child in node.children:
            if child.type == 'parenthesized_expression':
                # Extract condition
                for subchild in child.children:
                    if subchild.type not in ['(', ')']:
                        condition = self._normalize_node(subchild)
            elif child.type == 'block' and then_branch is None:
                then_branch = UnifiedASTNode(
                    type=NodeType.BLOCK,
                    children=self._normalize_block(child),
                    location=self._get_location(child)
                )
            elif child.type == 'block' and then_branch is not None:
                else_branch = UnifiedASTNode(
                    type=NodeType.BLOCK,
                    children=self._normalize_block(child),
                    location=self._get_location(child)
                )
        
        children = [condition] if condition else []
        if then_branch:
            children.append(then_branch)
        if else_branch:
            children.append(else_branch)
        
        return UnifiedASTNode(
            type=NodeType.CONDITIONAL,
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
        operator = None
        
        for child in node.children:
            if child.type in ['+', '-', '*', '/', '==', '!=', '<', '>', '<=', '>=', '&&', '||']:
                operator = self.parser.get_node_text(child)
            else:
                normalized = self._normalize_node(child)
                if normalized:
                    children.append(normalized)
        
        return UnifiedASTNode(
            type=NodeType.BINARY_OP,
            name=operator,
            children=children,
            location=self._get_location(node)
        )
    
    def _is_async_method(self, node: Node) -> bool:
        """Check if method is async (returns CompletableFuture, Mono, Flux, etc.).
        
        Args:
            node: Method declaration node
            
        Returns:
            True if async
        """
        for child in node.children:
            if child.type in ['generic_type', 'type_identifier']:
                type_text = self.parser.get_node_text(child)
                async_types = ['CompletableFuture', 'Mono', 'Flux', 'Future', 'ListenableFuture']
                if any(async_type in type_text for async_type in async_types):
                    return True
        return False
    
    def _find_child_by_type(self, node: Node, child_type: str) -> Optional[Node]:
        """Find first child node of given type.
        
        Args:
            node: Parent node
            child_type: Type to search for
            
        Returns:
            Child node or None
        """
        for child in node.children:
            if child.type == child_type:
                return child
        return None
    
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
            if n.type == 'string_literal':
                text = self.parser.get_node_text(n).strip('"')
                if text and len(text) > 1:
                    literals.append(text)
            for child in n.children:
                walk(child)
        walk(node)
        return literals
    
    def _extract_all_calls(self, node: Node) -> List[dict]:
        """Extract all method calls."""
        calls = []
        def walk(n):
            if n.type == 'method_invocation':
                func_name = None
                args = []
                for child in n.children:
                    if child.type in ['identifier', 'field_access']:
                        func_name = self.parser.get_node_text(child)
                    elif child.type == 'argument_list':
                        for arg in child.children:
                            if arg.type != ',':
                                arg_text = self.parser.get_node_text(arg)
                                args.append(arg_text if len(arg_text) < 150 else f"<long_{len(arg_text)}>")
                if func_name:
                    calls.append({'function': func_name, 'arguments': args, 'line': n.start_point[0] + 1})
            for child in n.children:
                walk(child)
        walk(node)
        return calls
    
    def _extract_imports(self, node: Node) -> List[str]:
        """Extract import statements."""
        imports = []
        def walk(n):
            if n.type == 'import_declaration':
                import_text = self.parser.get_node_text(n)
                if len(import_text) < 200:
                    imports.append(import_text)
            for child in n.children:
                walk(child)
        walk(node)
        return imports
    
    def _extract_assignments(self, node: Node) -> List[dict]:
        """Extract variable assignments."""
        assignments = []
        def walk(n):
            if n.type in ['local_variable_declaration', 'assignment_expression']:
                var_name = None
                value = None
                for child in n.children:
                    if child.type == 'variable_declarator':
                        for vc in child.children:
                            if vc.type == 'identifier':
                                var_name = self.parser.get_node_text(vc)
                            elif vc.type not in ['=']:
                                value = self.parser.get_node_text(vc)
                if var_name:
                    assignments.append({'variable': var_name, 'value': value or '<unknown>', 'line': n.start_point[0] + 1})
            for child in n.children:
                walk(child)
        walk(node)
        return assignments
    
    def _extract_return_expressions(self, node: Node) -> List[str]:
        """Extract return statements."""
        returns = []
        def walk(n):
            if n.type == 'return_statement':
                for child in n.children:
                    if child.type != 'return':
                        ret_text = self.parser.get_node_text(child)
                        returns.append(ret_text if len(ret_text) < 150 else f"<long_{len(ret_text)}>")
            for child in n.children:
                walk(child)
        walk(node)
        return returns
    
    def _extract_exception_handlers(self, node: Node) -> List[dict]:
        """Extract try-catch blocks."""
        handlers = []
        def walk(n):
            if n.type == 'try_statement':
                handler_info = {'line': n.start_point[0] + 1, 'catch_types': [], 'has_finally': False}
                for child in n.children:
                    if child.type == 'catch_clause':
                        for cc in child.children:
                            if cc.type == 'catch_formal_parameter':
                                for ccp in cc.children:
                                    if ccp.type in ['type_identifier', 'identifier']:
                                        handler_info['catch_types'].append(self.parser.get_node_text(ccp))
                    elif child.type == 'finally_clause':
                        handler_info['has_finally'] = True
                handlers.append(handler_info)
            for child in n.children:
                walk(child)
        walk(node)
        return handlers
    
    def _extract_control_flow(self, node: Node) -> dict:
        """Extract control flow structure."""
        has_conditionals = False
        has_loops = False
        has_exception_handling = False
        
        def check(n):
            nonlocal has_conditionals, has_loops, has_exception_handling
            if n.type in ['if_statement', 'switch_expression', 'ternary_expression']:
                has_conditionals = True
            elif n.type in ['for_statement', 'enhanced_for_statement', 'while_statement', 'do_statement']:
                has_loops = True
            elif n.type == 'try_statement':
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
            if n.type == 'method_invocation':
                text = self.parser.get_node_text(n)
                if 'System.getenv' in text:
                    for child in n.children:
                        if child.type == 'argument_list':
                            for arg in child.children:
                                if arg.type == 'string_literal':
                                    var_name = self.parser.get_node_text(arg).strip('"')
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
            if n.type == 'identifier':
                identifiers.append(self.parser.get_node_text(n))
            for child in n.children:
                identifiers.extend(extract_identifiers(child))
            return identifiers
        
        def find_deps(n: Node):
            if n.type in ['local_variable_declaration', 'assignment_expression']:
                var_name = None
                deps = []
                for child in n.children:
                    if child.type == 'variable_declarator':
                        for vc in child.children:
                            if vc.type == 'identifier':
                                var_name = self.parser.get_node_text(vc)
                            else:
                                deps = extract_identifiers(vc)
                if var_name and deps:
                    dependencies[var_name] = deps
            for child in n.children:
                find_deps(child)
        
        find_deps(node)
        return dependencies
