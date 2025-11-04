"""Go AST normalizer to unified AST."""

from typing import List, Optional
from tree_sitter import Node

from ..unified_ast import UnifiedASTNode, NodeType, SourceLocation


class GoASTNormalizer:
    """Normalizes Go tree-sitter AST to unified AST."""
    
    def __init__(self, parser):
        """Initialize normalizer.
        
        Args:
            parser: GoParser instance
        """
        self.parser = parser
    
    def normalize_function(self, node: Node) -> UnifiedASTNode:
        """Normalize a Go function to unified AST.
        
        Args:
            node: Function declaration or func literal node
            
        Returns:
            Unified function node
        """
        if node.type == 'func_literal':
            return self._normalize_func_literal(node)
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
    
    def _normalize_func_literal(self, node: Node) -> UnifiedASTNode:
        """Normalize function literal (anonymous function).
        
        Args:
            node: Func literal node
            
        Returns:
            Unified function node
        """
        params = []
        return_type = None
        
        # Extract parameters
        for child in node.children:
            if child.type == 'parameter_list':
                params = self._extract_parameters(child)
        
        # Extract body
        body_children = []
        for child in node.children:
            if child.type == 'block':
                body_children = self._normalize_block(child)
        
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
            return_type=return_type,
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
        
        # Extract function name
        for child in node.children:
            if child.type == 'identifier':
                func_name = self.parser.get_node_text(child)
                break
        
        # Extract parameters from first parameter_list (input parameters)
        # Go functions have two parameter_lists: inputs and outputs
        for child in node.children:
            if child.type == 'parameter_list':
                params = self._extract_parameters(child)
                break  # Only get the first one (input parameters)
        
        # Extract body
        body_children = []
        for child in node.children:
            if child.type == 'block':
                body_children = self._normalize_block(child)
        
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
            return_type=return_type,
            location=self._get_location(node),
            metadata={
                'string_literals': string_literals,
                'all_calls': all_calls,
                'control_flow': control_flow,
                'env_var_access': env_var_access,
                'variable_dependencies': variable_dependencies
            }
        )
    
    def _extract_parameters(self, params_node: Node) -> List[str]:
        """Extract parameter names from parameter list.
        
        Args:
            params_node: Parameter list node
            
        Returns:
            List of parameter names
        """
        params = []
        for child in params_node.children:
            if child.type == 'parameter_declaration':
                # Extract identifier from parameter (first child is usually the name)
                if child.children and child.children[0].type == 'identifier':
                    params.append(self.parser.get_node_text(child.children[0]))
            elif child.type == 'variadic_parameter_declaration':
                # Handle ...args
                if child.children and child.children[0].type == 'identifier':
                    params.append(self.parser.get_node_text(child.children[0]))
        return params
    
    def _normalize_block(self, node: Node) -> List[UnifiedASTNode]:
        """Normalize a block of statements.
        
        Args:
            node: Block node
            
        Returns:
            List of unified nodes
        """
        children = []
        for child in node.children:
            if child.type == 'statement_list':
                # Go wraps statements in a statement_list node
                for stmt in child.children:
                    normalized = self._normalize_node(stmt)
                    if normalized:
                        children.append(normalized)
            elif child.type not in ['{', '}']:
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
        if node.type == 'short_var_declaration':
            return self._normalize_short_var_declaration(node)
        elif node.type == 'var_declaration':
            return self._normalize_var_declaration(node)
        elif node.type == 'assignment_statement':
            return self._normalize_assignment(node)
        elif node.type == 'call_expression':
            return self._normalize_call(node)
        elif node.type == 'return_statement':
            return self._normalize_return(node)
        elif node.type == 'if_statement':
            return self._normalize_if(node)
        elif node.type in ['interpreted_string_literal', 'raw_string_literal', 'int_literal', 'float_literal', 'true', 'false', 'nil']:
            return self._normalize_literal(node)
        elif node.type == 'identifier':
            return UnifiedASTNode(
                type=NodeType.IDENTIFIER,
                name=self.parser.get_node_text(node),
                location=self._get_location(node)
            )
        elif node.type == 'selector_expression':
            return self._normalize_selector(node)
        elif node.type == 'index_expression':
            return self._normalize_index(node)
        elif node.type == 'type_assertion_expression':
            # Handle type assertions: value.(Type)
            for child in node.children:
                if child.type not in ['.', '(', ')', 'type_identifier']:
                    return self._normalize_node(child)
        elif node.type == 'binary_expression':
            return self._normalize_binary_op(node)
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
    
    def _normalize_short_var_declaration(self, node: Node) -> UnifiedASTNode:
        """Normalize short variable declaration (x := value).
        
        Args:
            node: Short var declaration node
            
        Returns:
            Unified assignment node
        """
        var_names = []
        value_node = None
        found_assignment = False
        
        # Pattern: expression_list := expression_list
        # First expression_list has variables, second has values
        for child in node.children:
            if child.type == ':=':
                found_assignment = True
            elif child.type == 'expression_list':
                if not found_assignment:
                    # Left side (variables)
                    for subchild in child.children:
                        if subchild.type == 'identifier':
                            var_names.append(self.parser.get_node_text(subchild))
                else:
                    # Right side (values) - take first value
                    for subchild in child.children:
                        if subchild.type != ',':
                            value_node = subchild
                            break
        
        value_child = self._normalize_node(value_node) if value_node else None
        
        # For simplicity, use first variable name
        var_name = var_names[0] if var_names else None
        
        return UnifiedASTNode(
            type=NodeType.ASSIGNMENT,
            name=var_name,
            children=[value_child] if value_child else [],
            location=self._get_location(node)
        )
    
    def _normalize_var_declaration(self, node: Node) -> UnifiedASTNode:
        """Normalize var declaration.
        
        Args:
            node: Var declaration node
            
        Returns:
            Unified assignment node
        """
        var_name = None
        value_node = None
        
        for child in node.children:
            if child.type == 'var_spec':
                for subchild in child.children:
                    if subchild.type == 'identifier':
                        var_name = self.parser.get_node_text(subchild)
                    elif subchild.type not in ['var', '=', 'type_identifier']:
                        value_node = subchild
        
        value_child = self._normalize_node(value_node) if value_node else None
        
        return UnifiedASTNode(
            type=NodeType.ASSIGNMENT,
            name=var_name,
            children=[value_child] if value_child else [],
            location=self._get_location(node)
        )
    
    def _normalize_assignment(self, node: Node) -> UnifiedASTNode:
        """Normalize assignment statement.
        
        Args:
            node: Assignment statement node
            
        Returns:
            Unified assignment node
        """
        var_name = None
        value_node = None
        
        children = list(node.children)
        if len(children) >= 3:
            # Pattern: identifier = value
            if children[0].type == 'expression_list':
                for subchild in children[0].children:
                    if subchild.type == 'identifier':
                        var_name = self.parser.get_node_text(subchild)
                        break
            elif children[0].type == 'identifier':
                var_name = self.parser.get_node_text(children[0])
            
            value_node = children[-1]
        
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
        # Extract function name and receiver
        func_name = None
        receiver_node = None
        
        for child in node.children:
            if child.type == 'identifier':
                func_name = self.parser.get_node_text(child)
            elif child.type == 'selector_expression':
                # Method call: obj.method()
                selector_normalized = self._normalize_selector(child)
                if selector_normalized:
                    func_name = selector_normalized.name
                    if selector_normalized.children:
                        receiver_node = selector_normalized.children[0]
            elif child.type == 'call_expression':
                # Chained call
                receiver_node = self._normalize_call(child)
        
        # Extract arguments
        args = []
        if receiver_node:
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
            name=func_name or self.parser.get_node_text(node),
            children=args,
            location=self._get_location(node)
        )
    
    def _normalize_selector(self, node: Node) -> UnifiedASTNode:
        """Normalize selector expression (obj.field).
        
        Args:
            node: Selector expression node
            
        Returns:
            Unified member access node
        """
        # Extract base and field
        base_node = None
        field_name = None
        
        for child in node.children:
            if child.type == 'identifier':
                if base_node is None:
                    base_node = UnifiedASTNode(
                        type=NodeType.IDENTIFIER,
                        name=self.parser.get_node_text(child),
                        location=self._get_location(child)
                    )
                else:
                    field_name = self.parser.get_node_text(child)
            elif child.type in ['selector_expression', 'call_expression']:
                base_node = self._normalize_node(child)
        
        full_name = self.parser.get_node_text(node)
        
        return UnifiedASTNode(
            type=NodeType.MEMBER_ACCESS,
            name=full_name,
            children=[base_node] if base_node else [],
            location=self._get_location(node)
        )
    
    def _normalize_index(self, node: Node) -> UnifiedASTNode:
        """Normalize index expression (arr[i]).
        
        Args:
            node: Index expression node
            
        Returns:
            Unified subscript node
        """
        obj_node = None
        index_node = None
        
        children = list(node.children)
        if len(children) >= 3:
            obj_node = self._normalize_node(children[0])
            # Index is between [ and ]
            for child in children:
                if child.type not in ['[', ']'] and child != children[0]:
                    index_node = self._normalize_node(child)
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
            if child.type == 'block':
                if then_branch is None:
                    then_branch = self._normalize_node(child)
                else:
                    else_branch = self._normalize_node(child)
            elif child.type not in ['if', 'else', '(', ')']:
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
            if child.type in ['+', '-', '*', '/', '%', '==', '!=', '<', '>', '<=', '>=', '&&', '||', '&', '|', '^', '<<', '>>']:
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
            if n.type in ['interpreted_string_literal', 'raw_string_literal']:
                text = self.parser.get_node_text(n).strip('"`')
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
                    if child.type in ['identifier', 'selector_expression']:
                        func_name = self.parser.get_node_text(child)
                    elif child.type == 'argument_list':
                        for arg in child.children:
                            if arg.type not in ['(', ')', ',']:
                                arg_text = self.parser.get_node_text(arg)
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
            if n.type in ['if_statement', 'expression_switch_statement', 'type_switch_statement']:
                has_conditionals = True
            elif n.type in ['for_statement', 'range_clause']:
                has_loops = True
            elif n.type in ['defer_statement', 'panic', 'recover']:
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
        """Extract environment variable accesses (os.Getenv)."""
        env_vars = []
        
        def find_env(n):
            if n.type == 'call_expression':
                text = self.parser.get_node_text(n)
                if 'os.Getenv' in text or 'os.LookupEnv' in text:
                    # Try to extract the env var name from arguments
                    for child in n.children:
                        if child.type == 'argument_list':
                            for arg in child.children:
                                if arg.type in ['interpreted_string_literal', 'raw_string_literal']:
                                    var_name = self.parser.get_node_text(arg).strip('"`')
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
            if n.type in ['short_var_declaration', 'var_declaration']:
                var_name = None
                deps = []
                for child in n.children:
                    if child.type == 'identifier':
                        var_name = self.parser.get_node_text(child)
                    elif child.type == 'expression_list':
                        deps = extract_identifiers(child)
                if var_name and deps:
                    dependencies[var_name] = deps
            for child in n.children:
                find_deps(child)
        
        find_deps(node)
        return dependencies
