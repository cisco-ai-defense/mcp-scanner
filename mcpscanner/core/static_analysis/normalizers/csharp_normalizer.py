"""C# AST normalizer for MCP Scanner."""

from typing import List, Optional
from tree_sitter import Node

from ..unified_ast import UnifiedASTNode, NodeType, SourceLocation


class CSharpASTNormalizer:
    """Normalizes C# AST to unified format."""
    
    def __init__(self, parser):
        """Initialize normalizer.
        
        Args:
            parser: CSharpParser instance
        """
        self.parser = parser
    
    def normalize_function(self, node: Node) -> UnifiedASTNode:
        """Normalize a C# method to unified AST.
        
        Args:
            node: Method declaration node
            
        Returns:
            Unified function node
        """
        if node.type == 'method_declaration':
            return self._normalize_method_declaration(node)
        else:
            # Fallback
            return UnifiedASTNode(
                type=NodeType.FUNCTION,
                name="<unknown>",
                parameters=[],
                location=self._get_location(node)
            )
    
    def _normalize_method_declaration(self, node: Node) -> UnifiedASTNode:
        """Normalize method declaration.
        
        Args:
            node: Method declaration node
            
        Returns:
            Unified function node
        """
        method_name = None
        params = []
        
        # Extract method name and parameters
        for child in node.children:
            if child.type == 'identifier':
                method_name = self.parser.get_node_text(child)
            elif child.type == 'parameter_list':
                params = self._extract_parameters(child)
        
        # Extract body
        body_children = []
        for child in node.children:
            if child.type == 'block':
                body_children = self._normalize_block(child)
            elif child.type == 'arrow_expression_clause':
                # Expression-bodied method: => expression
                body_children = [self._normalize_node(child)]
        
        # Extract rich context
        string_literals = self._extract_string_literals(node)
        all_calls = self._extract_all_calls(node)
        control_flow = self._extract_control_flow(node)
        env_var_access = self._extract_env_var_access(node)
        variable_dependencies = self._extract_variable_dependencies(node)
        
        return UnifiedASTNode(
            type=NodeType.FUNCTION,
            name=method_name or "<unknown>",
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
    
    def _extract_parameters(self, params_node: Node) -> List[str]:
        """Extract parameter names from parameter list.
        
        Args:
            params_node: Parameter list node
            
        Returns:
            List of parameter names
        """
        params = []
        for child in params_node.children:
            if child.type == 'parameter':
                # Parameter has type and name
                for subchild in child.children:
                    if subchild.type == 'identifier':
                        params.append(self.parser.get_node_text(subchild))
        return params
    
    def _normalize_block(self, node: Node) -> List[UnifiedASTNode]:
        """Normalize a block of statements.
        
        Args:
            node: Block node
            
        Returns:
            List of normalized child nodes
        """
        children = []
        for child in node.children:
            if child.type not in ['{', '}']:
                normalized = self._normalize_node(child)
                if normalized:
                    children.append(normalized)
        return children
    
    def _normalize_node(self, node: Node) -> Optional[UnifiedASTNode]:
        """Normalize a generic AST node.
        
        Args:
            node: AST node
            
        Returns:
            Unified AST node or None
        """
        if node.type == 'local_declaration_statement':
            return self._normalize_variable_declaration(node)
        elif node.type == 'expression_statement':
            return self._normalize_expression_statement(node)
        elif node.type == 'return_statement':
            return self._normalize_return(node)
        elif node.type == 'if_statement':
            return self._normalize_if_statement(node)
        elif node.type == 'for_statement' or node.type == 'foreach_statement':
            return self._normalize_loop(node)
        elif node.type == 'invocation_expression':
            return self._normalize_call(node)
        elif node.type == 'assignment_expression':
            return self._normalize_assignment(node)
        elif node.type == 'await_expression':
            return self._normalize_await(node)
        else:
            # Generic node - recurse into children
            children = []
            for child in node.children:
                normalized = self._normalize_node(child)
                if normalized:
                    children.append(normalized)
            
            if children:
                return UnifiedASTNode(
                    type=NodeType.EXPRESSION,
                    name=node.type,
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
        value = None
        
        # Extract variable name and value
        for child in node.children:
            if child.type == 'variable_declaration':
                for subchild in child.children:
                    if subchild.type == 'variable_declarator':
                        for item in subchild.children:
                            if item.type == 'identifier':
                                var_name = self.parser.get_node_text(item)
                            elif item.type == 'equals_value_clause':
                                # Get the value expression
                                for val_child in item.children:
                                    if val_child.type != '=':
                                        value = self.parser.get_node_text(val_child)
        
        return UnifiedASTNode(
            type=NodeType.ASSIGNMENT,
            name=var_name or "<unknown>",
            value=value,
            location=self._get_location(node)
        )
    
    def _normalize_expression_statement(self, node: Node) -> Optional[UnifiedASTNode]:
        """Normalize expression statement.
        
        Args:
            node: Expression statement node
            
        Returns:
            Normalized expression
        """
        # Expression statement wraps the actual expression
        for child in node.children:
            if child.type != ';':
                return self._normalize_node(child)
        return None
    
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
                return_value = self.parser.get_node_text(child)
        
        return UnifiedASTNode(
            type=NodeType.RETURN,
            value=return_value,
            location=self._get_location(node)
        )
    
    def _normalize_if_statement(self, node: Node) -> UnifiedASTNode:
        """Normalize if statement.
        
        Args:
            node: If statement node
            
        Returns:
            Unified conditional node
        """
        condition = None
        then_branch = []
        else_branch = []
        
        for child in node.children:
            if child.type == 'parenthesized_expression':
                condition = self.parser.get_node_text(child)
            elif child.type == 'block':
                if not then_branch:
                    then_branch = self._normalize_block(child)
                else:
                    else_branch = self._normalize_block(child)
        
        return UnifiedASTNode(
            type=NodeType.CONDITIONAL,
            condition=condition,
            children=then_branch + else_branch,
            location=self._get_location(node)
        )
    
    def _normalize_loop(self, node: Node) -> UnifiedASTNode:
        """Normalize loop statement.
        
        Args:
            node: Loop node
            
        Returns:
            Unified loop node
        """
        body = []
        for child in node.children:
            if child.type == 'block':
                body = self._normalize_block(child)
        
        return UnifiedASTNode(
            type=NodeType.LOOP,
            children=body,
            location=self._get_location(node)
        )
    
    def _normalize_call(self, node: Node) -> UnifiedASTNode:
        """Normalize method invocation.
        
        Args:
            node: Invocation expression node
            
        Returns:
            Unified call node
        """
        func_name = None
        args = []
        
        # Extract function name and arguments
        for child in node.children:
            if child.type in ['identifier', 'member_access_expression']:
                func_name = self.parser.get_node_text(child)
            elif child.type == 'argument_list':
                for arg_child in child.children:
                    if arg_child.type == 'argument':
                        args.append(self.parser.get_node_text(arg_child))
        
        return UnifiedASTNode(
            type=NodeType.CALL,
            name=func_name or "<unknown>",
            metadata={'arguments': args},
            location=self._get_location(node)
        )
    
    def _normalize_assignment(self, node: Node) -> UnifiedASTNode:
        """Normalize assignment expression.
        
        Args:
            node: Assignment expression node
            
        Returns:
            Unified assignment node
        """
        var_name = None
        value = None
        
        children = list(node.children)
        if len(children) >= 3:
            var_name = self.parser.get_node_text(children[0])
            value = self.parser.get_node_text(children[2])
        
        return UnifiedASTNode(
            type=NodeType.ASSIGNMENT,
            name=var_name or "<unknown>",
            value=value,
            location=self._get_location(node)
        )
    
    def _normalize_await(self, node: Node) -> UnifiedASTNode:
        """Normalize await expression.
        
        Args:
            node: Await expression node
            
        Returns:
            Unified await node
        """
        expr = None
        for child in node.children:
            if child.type != 'await':
                expr = self._normalize_node(child)
        
        return UnifiedASTNode(
            type=NodeType.AWAIT,
            children=[expr] if expr else [],
            location=self._get_location(node)
        )
    
    def _get_location(self, node: Node) -> SourceLocation:
        """Get location information for a node.
        
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
            if n.type in ['string_literal', 'verbatim_string_literal', 'interpolated_string_expression']:
                text = self.parser.get_node_text(n).strip('"@$')
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
            if n.type == 'invocation_expression':
                func_name = None
                args = []
                for child in n.children:
                    if child.type in ['identifier', 'member_access_expression']:
                        func_name = self.parser.get_node_text(child)
                    elif child.type == 'argument_list':
                        for arg in child.children:
                            if arg.type == 'argument':
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
            if n.type in ['if_statement', 'switch_statement', 'conditional_expression']:
                has_conditionals = True
            elif n.type in ['for_statement', 'foreach_statement', 'while_statement', 'do_statement']:
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
        """Extract environment variable accesses (Environment.GetEnvironmentVariable)."""
        env_vars = []
        
        def find_env(n):
            if n.type == 'invocation_expression':
                text = self.parser.get_node_text(n)
                if 'Environment.GetEnvironmentVariable' in text:
                    for child in n.children:
                        if child.type == 'argument_list':
                            for arg in child.children:
                                if arg.type == 'argument':
                                    for ac in arg.children:
                                        if ac.type == 'string_literal':
                                            var_name = self.parser.get_node_text(ac).strip('"')
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
            if n.type in ['variable_declaration', 'local_declaration_statement']:
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
