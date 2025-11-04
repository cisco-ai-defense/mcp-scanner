"""Swift AST normalizer to unified AST."""

from typing import List, Optional
from tree_sitter import Node

from ..unified_ast import UnifiedASTNode, NodeType, SourceLocation


class SwiftASTNormalizer:
    """Normalizes Swift tree-sitter AST to unified AST."""
    
    def __init__(self, parser):
        """Initialize normalizer.
        
        Args:
            parser: SwiftParser instance
        """
        self.parser = parser
    
    def normalize_function(self, node: Node) -> UnifiedASTNode:
        """Normalize a Swift function/closure to unified AST.
        
        Args:
            node: Function declaration, closure expression, or switch_entry node
            
        Returns:
            Unified function node
        """
        if node.type in ['closure_expression', 'lambda_literal']:
            return self._normalize_closure(node)
        elif node.type == 'function_declaration':
            return self._normalize_function_declaration(node)
        elif node.type == 'switch_entry':
            return self._normalize_switch_case(node)
        else:
            # Fallback
            return UnifiedASTNode(
                type=NodeType.FUNCTION,
                name="<unknown>",
                parameters=[],
                location=self._get_location(node)
            )
    
    def _normalize_closure(self, node: Node) -> UnifiedASTNode:
        """Normalize closure expression.
        
        Args:
            node: Closure expression node
            
        Returns:
            Unified function node
        """
        params = []
        
        # Extract parameters from closure signature
        for child in node.children:
            if child.type == 'closure_parameters':
                params = self._extract_closure_parameters(child)
            elif child.type == 'lambda_function_type':
                # For lambda literals - check if it has parameters
                params = self._extract_lambda_type_parameters(child)
            elif child.type == 'lambda_function_type_parameters':
                # Direct lambda parameters
                params = self._extract_lambda_parameters(child)
        
        # Extract body
        body_children = []
        for child in node.children:
            if child.type == 'statements':
                body_children = self._normalize_statements(child)
        
        return UnifiedASTNode(
            type=NodeType.FUNCTION,
            name="<lambda>",
            parameters=params,
            children=body_children,
            location=self._get_location(node)
        )
    
    def _normalize_switch_case(self, node: Node) -> UnifiedASTNode:
        """Normalize a switch case (tool handler).
        
        Args:
            node: Switch entry node
            
        Returns:
            Unified function node with tool name
        """
        tool_name = None
        params = ['params']  # Swift CallTool handlers use 'params'
        
        # Extract tool name from case pattern (e.g., case "read_file":)
        for child in node.children:
            if child.type == 'switch_pattern':
                # The pattern contains the string literal
                for subchild in child.children:
                    if subchild.type == 'pattern':
                        # Get the text of the pattern (includes quotes)
                        text = self.parser.get_node_text(subchild)
                        # Remove quotes
                        tool_name = text.strip('"').strip("'")
                        break
        
        # Extract body statements
        body_children = []
        for child in node.children:
            if child.type == 'statements':
                body_children = self._normalize_statements(child)
        
        return UnifiedASTNode(
            type=NodeType.FUNCTION,
            name=tool_name or "<unknown_tool>",
            parameters=params,
            children=body_children,
            location=self._get_location(node)
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
        
        # Extract function name
        for child in node.children:
            if child.type == 'simple_identifier':
                func_name = self.parser.get_node_text(child)
                break
        
        # Extract parameters
        for child in node.children:
            if child.type == 'function_value_parameters':
                params = self._extract_function_parameters(child)
        
        # Extract body
        body_children = []
        for child in node.children:
            if child.type == 'function_body':
                for subchild in child.children:
                    if subchild.type == 'statements':
                        body_children = self._normalize_statements(subchild)
        
        # Extract rich context
        string_literals = self._extract_string_literals(node)
        all_calls = self._extract_all_calls(node)
        control_flow = self._extract_control_flow(node)
        env_var_access = self._extract_env_var_access(node)
        variable_dependencies = self._extract_variable_dependencies(node)
        
        return UnifiedASTNode(
            type=NodeType.FUNCTION,
            name=func_name or "<anonymous>",
            parameters=params,
            children=body_children,
            location=self._get_location(node),
            metadata={
                'string_literals': string_literals,
                'all_calls': all_calls,
                'control_flow': control_flow,
                'env_var_access': env_var_access,
                'variable_dependencies': variable_dependencies
            }
        )
    
    def _extract_closure_parameters(self, params_node: Node) -> List[str]:
        """Extract parameter names from closure parameters.
        
        Args:
            params_node: Closure parameters node
            
        Returns:
            List of parameter names
        """
        params = []
        for child in params_node.children:
            if child.type == 'closure_parameter':
                for subchild in child.children:
                    if subchild.type == 'simple_identifier':
                        params.append(self.parser.get_node_text(subchild))
        return params
    
    def _extract_lambda_parameters(self, params_node: Node) -> List[str]:
        """Extract parameter names from lambda parameters.
        
        Args:
            params_node: Lambda parameters node (lambda_function_type_parameters)
            
        Returns:
            List of parameter names
        """
        params = []
        for child in params_node.children:
            if child.type == 'lambda_parameter':
                # Lambda parameter contains simple_identifier
                for subchild in child.children:
                    if subchild.type == 'simple_identifier':
                        params.append(self.parser.get_node_text(subchild))
            elif child.type == 'simple_identifier':
                params.append(self.parser.get_node_text(child))
        return params
    
    def _extract_lambda_type_parameters(self, lambda_type_node: Node) -> List[str]:
        """Extract parameter names from lambda_function_type.
        
        Args:
            lambda_type_node: Lambda function type node
            
        Returns:
            List of parameter names
        """
        params = []
        for child in lambda_type_node.children:
            if child.type == 'lambda_function_type_parameters':
                params = self._extract_lambda_parameters(child)
        return params
    
    def _extract_function_parameters(self, params_node: Node) -> List[str]:
        """Extract parameter names from function parameters.
        
        Args:
            params_node: Function parameters node
            
        Returns:
            List of parameter names
        """
        params = []
        for child in params_node.children:
            if child.type == 'function_value_parameter':
                # Swift parameters can have external and internal names
                # We want the internal name (the one used in the function body)
                identifiers = []
                for subchild in child.children:
                    if subchild.type == 'simple_identifier':
                        identifiers.append(self.parser.get_node_text(subchild))
                # If there are two identifiers, the second is the internal name
                if len(identifiers) >= 2:
                    params.append(identifiers[1])
                elif len(identifiers) == 1:
                    params.append(identifiers[0])
        return params
    
    def _normalize_statements(self, node: Node) -> List[UnifiedASTNode]:
        """Normalize a statements block.
        
        Args:
            node: Statements node
            
        Returns:
            List of unified nodes
        """
        children = []
        for child in node.children:
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
            return self._normalize_property_declaration(node)
        elif node.type == 'call_expression':
            return self._normalize_call(node)
        elif node.type == 'return_statement':
            return self._normalize_return(node)
        elif node.type == 'if_statement':
            return self._normalize_if(node)
        elif node.type in ['line_string_literal', 'integer_literal', 'boolean_literal', 'nil']:
            return self._normalize_literal(node)
        elif node.type == 'simple_identifier':
            return UnifiedASTNode(
                type=NodeType.IDENTIFIER,
                name=self.parser.get_node_text(node),
                location=self._get_location(node)
            )
        elif node.type == 'navigation_expression':
            return self._normalize_navigation(node)
        elif node.type == 'subscript_expression':
            return self._normalize_subscript(node)
        elif node.type == 'as_expression':
            # Handle type casts: value as Type
            for child in node.children:
                if child.type not in ['as', 'type_identifier', 'user_type']:
                    return self._normalize_node(child)
        elif node.type == 'try_expression':
            # Handle try expressions: try someFunction()
            for child in node.children:
                if child.type != 'try':
                    return self._normalize_node(child)
        elif node.type == 'await_expression':
            # Handle await expressions: await someFunction()
            for child in node.children:
                if child.type != 'await':
                    return self._normalize_node(child)
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
    
    def _normalize_property_declaration(self, node: Node) -> UnifiedASTNode:
        """Normalize property declaration (let/var).
        
        Args:
            node: Property declaration node
            
        Returns:
            Unified assignment node
        """
        var_name = None
        value_node = None
        
        for child in node.children:
            if child.type == 'pattern':
                for subchild in child.children:
                    if subchild.type == 'simple_identifier':
                        var_name = self.parser.get_node_text(subchild)
            elif child.type not in ['let', 'var', '=', 'type_annotation']:
                value_node = child
        
        value_child = self._normalize_node(value_node) if value_node else None
        
        return UnifiedASTNode(
            type=NodeType.ASSIGNMENT,
            name=var_name,
            children=[value_child] if value_child else [],
            location=self._get_location(node)
        )
    
    def _normalize_call(self, node: Node) -> UnifiedASTNode:
        """Normalize function call.
        
        Args:
            node: Call expression node
            
        Returns:
            Unified call node
        """
        # Extract function name
        func_name = None
        receiver_node = None
        
        for child in node.children:
            if child.type == 'simple_identifier':
                func_name = self.parser.get_node_text(child)
            elif child.type == 'navigation_expression':
                # Method call: obj.method()
                nav_normalized = self._normalize_navigation(child)
                if nav_normalized:
                    func_name = nav_normalized.name
                    if nav_normalized.children:
                        receiver_node = nav_normalized.children[0]
        
        # Extract arguments
        args = []
        if receiver_node:
            args.append(receiver_node)
        
        for child in node.children:
            if child.type == 'call_suffix':
                for subchild in child.children:
                    if subchild.type == 'value_arguments':
                        for arg_child in subchild.children:
                            if arg_child.type == 'value_argument':
                                for val in arg_child.children:
                                    if val.type not in [':', ',', '(', ')']:
                                        normalized_arg = self._normalize_node(val)
                                        if normalized_arg:
                                            args.append(normalized_arg)
        
        return UnifiedASTNode(
            type=NodeType.CALL,
            name=func_name or self.parser.get_node_text(node),
            children=args,
            location=self._get_location(node)
        )
    
    def _normalize_navigation(self, node: Node) -> UnifiedASTNode:
        """Normalize navigation expression (obj.field).
        
        Args:
            node: Navigation expression node
            
        Returns:
            Unified member access node
        """
        # Extract base and field
        base_node = None
        field_name = None
        
        children = list(node.children)
        if len(children) >= 2:
            # First child is the base
            base_node = self._normalize_node(children[0])
            # Last child is typically the field
            if children[-1].type == 'simple_identifier':
                field_name = self.parser.get_node_text(children[-1])
        
        full_name = self.parser.get_node_text(node)
        
        return UnifiedASTNode(
            type=NodeType.MEMBER_ACCESS,
            name=full_name,
            children=[base_node] if base_node else [],
            location=self._get_location(node)
        )
    
    def _normalize_subscript(self, node: Node) -> UnifiedASTNode:
        """Normalize subscript expression (arr[i]).
        
        Args:
            node: Subscript expression node
            
        Returns:
            Unified subscript node
        """
        obj_node = None
        index_node = None
        
        children = list(node.children)
        if len(children) >= 1:
            obj_node = self._normalize_node(children[0])
            # Index is in the subscript arguments
            for child in children:
                if child.type == 'value_arguments':
                    for arg in child.children:
                        if arg.type not in ['[', ']', ',']:
                            index_node = self._normalize_node(arg)
                            break
        
        args = []
        if obj_node:
            args.append(obj_node)
        if index_node:
            args.append(index_node)
        
        return UnifiedASTNode(
            type=NodeType.SUBSCRIPT,
            name=self.parser.get_node_text(node),
            children=args,
            location=self._get_location(node)
        )
    
    def _normalize_return(self, node: Node) -> UnifiedASTNode:
        """Normalize return statement.
        
        Args:
            node: Return statement node
            
        Returns:
            Unified return node
        """
        return_values = []
        for child in node.children:
            if child.type != 'return':
                normalized = self._normalize_node(child)
                if normalized:
                    return_values.append(normalized)
        
        return UnifiedASTNode(
            type=NodeType.RETURN,
            children=return_values,
            location=self._get_location(node)
        )
    
    def _normalize_if(self, node: Node) -> UnifiedASTNode:
        """Normalize if statement.
        
        Args:
            node: If statement node
            
        Returns:
            Unified if node
        """
        condition = None
        then_branch = None
        else_branch = None
        
        for child in node.children:
            if child.type == 'if_statement_body':
                if then_branch is None:
                    then_branch = self._normalize_node(child)
                else:
                    else_branch = self._normalize_node(child)
            elif child.type not in ['if', 'else']:
                if condition is None:
                    condition = self._normalize_node(child)
        
        children = []
        if condition:
            children.append(condition)
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
            if n.type in ['line_string_literal', 'multi_line_string_literal']:
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
            if n.type in ['if_statement', 'guard_statement', 'switch_statement']:
                has_conditionals = True
            elif n.type in ['for_statement', 'while_statement', 'repeat_while_statement']:
                has_loops = True
            elif n.type in ['do_statement', 'catch_clause']:
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
        """Extract environment variable accesses (ProcessInfo.processInfo.environment)."""
        env_vars = []
        
        def find_env(n):
            if n.type == 'call_expression':
                text = self.parser.get_node_text(n)
                if 'environment[' in text or 'getenv' in text:
                    for child in n.children:
                        if child.type == 'value_arguments':
                            for va in child.children:
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
                    if child.type == 'pattern':
                        for pc in child.children:
                            if pc.type == 'simple_identifier':
                                var_name = self.parser.get_node_text(pc)
                    else:
                        deps = extract_identifiers(child)
                if var_name and deps:
                    dependencies[var_name] = deps
            for child in n.children:
                find_deps(child)
        
        find_deps(node)
        return dependencies
