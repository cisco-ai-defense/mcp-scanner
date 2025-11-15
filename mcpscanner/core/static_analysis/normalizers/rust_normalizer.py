"""Rust AST normalizer for MCP Scanner."""

from typing import List, Optional
from tree_sitter import Node

from ..unified_ast import UnifiedASTNode, NodeType, SourceLocation


class RustASTNormalizer:
    """Normalizes Rust AST to unified format."""
    
    def __init__(self, parser):
        """Initialize normalizer.
        
        Args:
            parser: RustParser instance
        """
        self.parser = parser
    
    def normalize_function(self, node: Node) -> UnifiedASTNode:
        """Normalize a Rust function to unified AST.
        
        Args:
            node: Function node
            
        Returns:
            Unified function node
        """
        if node.type == 'function_item':
            return self._normalize_function_item(node)
        else:
            # Fallback
            return UnifiedASTNode(
                type=NodeType.FUNCTION,
                name="<unknown>",
                parameters=[],
                location=self._get_location(node)
            )
    
    def _normalize_function_item(self, node: Node) -> UnifiedASTNode:
        """Normalize function item.
        
        Args:
            node: Function item node
            
        Returns:
            Unified function node
        """
        func_name = None
        params = []
        is_async = False
        
        # Extract function name, parameters, and async status
        for child in node.children:
            if child.type == 'identifier':
                func_name = self.parser.get_node_text(child)
            elif child.type == 'parameters':
                params = self._extract_parameters(child)
            elif child.type == 'async':
                is_async = True
        
        # Extract body
        body_children = []
        for child in node.children:
            if child.type == 'block':
                body_children = self._normalize_block(child)
        
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
            name=func_name or "<unknown>",
            parameters=params,
            children=body_children,
            is_async=is_async,
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
    
    def _extract_parameters(self, params_node: Node) -> List[str]:
        """Extract parameter names.
        
        Args:
            params_node: Parameters node
            
        Returns:
            List of parameter names
        """
        params = []
        for child in params_node.children:
            if child.type == 'parameter':
                # Extract parameter name
                for param_child in child.children:
                    if param_child.type == 'identifier':
                        params.append(self.parser.get_node_text(param_child))
                        break
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
        if node.type == 'let_declaration':
            return self._normalize_let_declaration(node)
        elif node.type == 'call_expression':
            return self._normalize_call(node)
        elif node.type == 'return_expression':
            return self._normalize_return(node)
        elif node.type == 'if_expression':
            return self._normalize_conditional(node)
        elif node.type in ['while_expression', 'loop_expression', 'for_expression']:
            return self._normalize_loop(node)
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
                    type=NodeType.STATEMENT,
                    name=node.type,
                    children=children,
                    location=self._get_location(node)
                )
        
        return None
    
    def _normalize_let_declaration(self, node: Node) -> UnifiedASTNode:
        """Normalize let declaration (variable assignment).
        
        Args:
            node: Let declaration node
            
        Returns:
            Unified assignment node
        """
        var_name = None
        value = None
        
        for child in node.children:
            if child.type == 'identifier':
                var_name = self.parser.get_node_text(child)
            elif child.type not in ['let', '=', ';']:
                value = self.parser.get_node_text(child)
        
        return UnifiedASTNode(
            type=NodeType.ASSIGNMENT,
            name=var_name or "<unknown>",
            value=value,
            location=self._get_location(node)
        )
    
    def _normalize_call(self, node: Node) -> UnifiedASTNode:
        """Normalize function call.
        
        Args:
            node: Call expression node
            
        Returns:
            Unified call node
        """
        func_name = None
        args = []
        
        # Extract function name
        for child in node.children:
            if child.type in ['identifier', 'field_expression', 'scoped_identifier']:
                func_name = self.parser.get_node_text(child)
                break
        
        # Extract arguments
        for child in node.children:
            if child.type == 'arguments':
                for arg_child in child.children:
                    if arg_child.type not in ['(', ')', ',']:
                        args.append(self.parser.get_node_text(arg_child))
        
        return UnifiedASTNode(
            type=NodeType.CALL,
            name=func_name or self.parser.get_node_text(node)[:50],
            metadata={'arguments': args},
            location=self._get_location(node)
        )
    
    def _normalize_return(self, node: Node) -> UnifiedASTNode:
        """Normalize return expression.
        
        Args:
            node: Return node
            
        Returns:
            Unified return node
        """
        return_value = None
        for child in node.children:
            if child.type != 'return':
                return_value = self.parser.get_node_text(child)
        
        return UnifiedASTNode(
            type=NodeType.RETURN,
            value=return_value,
            location=self._get_location(node)
        )
    
    def _normalize_conditional(self, node: Node) -> UnifiedASTNode:
        """Normalize conditional expression.
        
        Args:
            node: Conditional node
            
        Returns:
            Unified conditional node
        """
        condition = None
        then_branch = []
        else_branch = []
        
        for child in node.children:
            if child.type in ['binary_expression', 'identifier', 'call_expression']:
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
        """Normalize loop expression.
        
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
            type=NodeType.WHILE,  # Use WHILE for all loop types
            children=body,
            location=self._get_location(node)
        )
    
    def _normalize_await(self, node: Node) -> UnifiedASTNode:
        """Normalize await expression.
        
        Args:
            node: Await node
            
        Returns:
            Unified await node
        """
        expr = None
        for child in node.children:
            if child.type != '.await':
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
            if n.type in ['string_literal', 'raw_string_literal']:
                text = self.parser.get_node_text(n)
                # Clean up quotes
                text = text.strip('"\'r#')
                if text and len(text) > 1:
                    literals.append(text)
            
            # Recurse into children
            for child in n.children:
                walk_for_strings(child)
        
        walk_for_strings(node)
        return literals
    
    def _extract_all_calls(self, node: Node) -> List[str]:
        """Extract ALL function calls with their arguments.
        
        Let the LLM decide what's dangerous - no hardcoded patterns!
        
        Args:
            node: AST node to search
            
        Returns:
            List of dicts with call details
        """
        all_calls = []
        
        def extract_call(n: Node):
            if n.type == 'call_expression':
                # Extract function name
                func_node = n.child_by_field_name('function') if hasattr(n, 'child_by_field_name') else None
                func_name = None
                
                for child in n.children:
                    if child.type in ['identifier', 'field_expression', 'scoped_identifier']:
                        func_name = self.parser.get_node_text(child)
                        break
                
                # Extract arguments
                args = []
                for child in n.children:
                    if child.type == 'arguments':
                        for arg_child in child.children:
                            if arg_child.type not in ['(', ')', ',']:
                                arg_text = self.parser.get_node_text(arg_child)
                                if len(arg_text) < 150:
                                    args.append(arg_text)
                                else:
                                    args.append(f"<long_arg_{len(arg_text)}_chars>")
                
                if func_name:
                    all_calls.append({
                        'function': func_name,
                        'arguments': args,
                        'line': n.start_point[0] + 1
                    })
            
            for child in n.children:
                extract_call(child)
        
        extract_call(node)
        return all_calls
    
    def _extract_imports(self, node: Node) -> List[str]:
        """Extract all use statements.
        
        Returns:
            List of import statements
        """
        imports = []
        
        def find_imports(n: Node):
            if n.type == 'use_declaration':
                import_text = self.parser.get_node_text(n)
                if len(import_text) < 200:
                    imports.append(import_text)
            
            for child in n.children:
                find_imports(child)
        
        find_imports(node)
        return imports
    
    def _extract_assignments(self, node: Node) -> List[dict]:
        """Extract all variable assignments (let statements).
        
        Returns:
            List of assignment info
        """
        assignments = []
        
        def find_assignments(n: Node):
            if n.type == 'let_declaration':
                var_name = None
                value = None
                
                for child in n.children:
                    if child.type == 'identifier':
                        var_name = self.parser.get_node_text(child)
                    elif child.type not in ['let', '=', ';', 'mut']:
                        value_text = self.parser.get_node_text(child)
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
    
    def _extract_return_expressions(self, node: Node) -> List[str]:
        """Extract all return expressions.
        
        Returns:
            List of return expression strings
        """
        returns = []
        
        def find_returns(n: Node):
            if n.type == 'return_expression':
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
    
    def _extract_exception_handlers(self, node: Node) -> List[dict]:
        """Extract all match expressions (Rust's error handling).
        
        Returns:
            List of exception handler info
        """
        handlers = []
        
        def find_handlers(n: Node):
            if n.type == 'match_expression':
                handler_info = {
                    'line': n.start_point[0] + 1,
                    'match_arms': []
                }
                
                for child in n.children:
                    if child.type == 'match_arm':
                        # Extract pattern
                        pattern_text = None
                        for arm_child in child.children:
                            if arm_child.type == 'match_pattern':
                                pattern_text = self.parser.get_node_text(arm_child)
                                break
                        
                        if pattern_text and len(pattern_text) < 100:
                            handler_info['match_arms'].append(pattern_text)
                
                if handler_info['match_arms']:
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
        
        def check(n):
            nonlocal has_conditionals, has_loops, has_exception_handling
            if n.type in ['if_expression', 'match_expression']:
                has_conditionals = True
            elif n.type in ['loop_expression', 'while_expression', 'for_expression']:
                has_loops = True
            elif n.type == 'match_expression':
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
        """Extract environment variable accesses (env::var)."""
        env_vars = []
        
        def find_env(n):
            if n.type == 'call_expression':
                text = self.parser.get_node_text(n)
                if 'env::var' in text or 'std::env::var' in text:
                    for child in n.children:
                        if child.type == 'arguments':
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
            if n.type == 'let_declaration':
                var_name = None
                deps = []
                for child in n.children:
                    if child.type == 'identifier':
                        var_name = self.parser.get_node_text(child)
                    elif child.type not in ['let', '=', ';', 'mut']:
                        deps = extract_identifiers(child)
                if var_name and deps:
                    dependencies[var_name] = deps
            for child in n.children:
                find_deps(child)
        
        find_deps(node)
        return dependencies
