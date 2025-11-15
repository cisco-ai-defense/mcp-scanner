"""Ruby AST normalizer for MCP Scanner."""

from typing import List, Optional
from tree_sitter import Node

from ..unified_ast import UnifiedASTNode, NodeType, SourceLocation


class RubyASTNormalizer:
    """Normalizes Ruby AST to unified format."""
    
    def __init__(self, parser):
        """Initialize normalizer.
        
        Args:
            parser: RubyParser instance
        """
        self.parser = parser
    
    def normalize_function(self, node: Node) -> UnifiedASTNode:
        """Normalize a Ruby method/block to unified AST.
        
        Args:
            node: Method or block node
            
        Returns:
            Unified function node
        """
        if node.type in ['method', 'singleton_method']:
            return self._normalize_method(node)
        elif node.type in ['block', 'do_block']:
            return self._normalize_block(node)
        else:
            # Fallback
            return UnifiedASTNode(
                type=NodeType.FUNCTION,
                name="<unknown>",
                parameters=[],
                location=self._get_location(node)
            )
    
    def _normalize_method(self, node: Node) -> UnifiedASTNode:
        """Normalize method declaration.
        
        Args:
            node: Method node
            
        Returns:
            Unified function node
        """
        method_name = None
        params = []
        
        # Extract method name and parameters
        for child in node.children:
            if child.type == 'identifier':
                method_name = self.parser.get_node_text(child)
            elif child.type in ['method_parameters', 'parameters']:
                params = self._extract_parameters(child)
        
        # Extract body
        body_children = []
        for child in node.children:
            if child.type in ['body_statement', 'block_body']:
                body_children = self._normalize_body(child)
        
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
            name=method_name or "<unknown>",
            parameters=params,
            children=body_children,
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
    
    def _normalize_block(self, node: Node) -> UnifiedASTNode:
        """Normalize block (lambda/proc).
        
        Args:
            node: Block node
            
        Returns:
            Unified function node
        """
        params = []
        
        # Extract block parameters
        for child in node.children:
            if child.type == 'block_parameters':
                params = self._extract_parameters(child)
        
        # Extract body
        body_children = []
        for child in node.children:
            if child.type in ['block_body', 'body_statement']:
                body_children = self._normalize_body(child)
        
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
            name="<block>",
            parameters=params,
            children=body_children,
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
            if child.type in ['identifier', 'keyword_parameter', 'optional_parameter']:
                # Get the identifier
                for subchild in child.children:
                    if subchild.type == 'identifier':
                        params.append(self.parser.get_node_text(subchild))
                        break
                else:
                    # If no identifier child, the node itself might be the identifier
                    if child.type == 'identifier':
                        params.append(self.parser.get_node_text(child))
        return params
    
    def _normalize_body(self, node: Node) -> List[UnifiedASTNode]:
        """Normalize a body of statements.
        
        Args:
            node: Body node
            
        Returns:
            List of normalized child nodes
        """
        children = []
        for child in node.children:
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
        if node.type == 'assignment':
            return self._normalize_assignment(node)
        elif node.type == 'call':
            return self._normalize_call(node)
        elif node.type == 'return_statement':
            return self._normalize_return(node)
        elif node.type in ['if', 'unless', 'if_modifier', 'unless_modifier']:
            return self._normalize_conditional(node)
        elif node.type in ['while', 'until', 'for']:
            return self._normalize_loop(node)
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
    
    def _normalize_assignment(self, node: Node) -> UnifiedASTNode:
        """Normalize assignment.
        
        Args:
            node: Assignment node
            
        Returns:
            Unified assignment node
        """
        var_name = None
        value = None
        
        children = list(node.children)
        if len(children) >= 2:
            var_name = self.parser.get_node_text(children[0])
            value = self.parser.get_node_text(children[-1])
        
        return UnifiedASTNode(
            type=NodeType.ASSIGNMENT,
            name=var_name or "<unknown>",
            value=value,
            location=self._get_location(node)
        )
    
    def _normalize_call(self, node: Node) -> UnifiedASTNode:
        """Normalize method call.
        
        Args:
            node: Call node
            
        Returns:
            Unified call node
        """
        func_name = None
        args = []
        
        # Extract method name
        for child in node.children:
            if child.type in ['identifier', 'constant']:
                func_name = self.parser.get_node_text(child)
                break
        
        # Extract arguments
        for child in node.children:
            if child.type == 'argument_list':
                for arg_child in child.children:
                    if arg_child.type != ',':
                        args.append(self.parser.get_node_text(arg_child))
        
        return UnifiedASTNode(
            type=NodeType.CALL,
            name=func_name or self.parser.get_node_text(node)[:50],
            metadata={'arguments': args},
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
                return_value = self.parser.get_node_text(child)
        
        return UnifiedASTNode(
            type=NodeType.RETURN,
            value=return_value,
            location=self._get_location(node)
        )
    
    def _normalize_conditional(self, node: Node) -> UnifiedASTNode:
        """Normalize conditional statement.
        
        Args:
            node: Conditional node
            
        Returns:
            Unified conditional node
        """
        condition = None
        then_branch = []
        else_branch = []
        
        for child in node.children:
            if child.type in ['binary', 'call', 'identifier']:
                condition = self.parser.get_node_text(child)
            elif child.type in ['then', 'body_statement']:
                then_branch = self._normalize_body(child)
            elif child.type == 'else':
                else_branch = self._normalize_body(child)
        
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
            if child.type in ['do', 'body_statement']:
                body = self._normalize_body(child)
        
        return UnifiedASTNode(
            type=NodeType.LOOP,
            children=body,
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
        
        This helps the LLM see URLs, file paths, and other string constants
        that might indicate malicious behavior.
        
        Args:
            node: AST node to search
            
        Returns:
            List of string literal values
        """
        literals = []
        
        def walk_for_strings(n: Node):
            # Check if this node is a string
            if n.type in ['string', 'string_content', 'simple_symbol', 'heredoc_body']:
                text = self.parser.get_node_text(n)
                # Clean up quotes and symbols
                text = text.strip('"\'`:')
                if text and len(text) > 1:  # Skip empty or single-char strings
                    literals.append(text)
            
            # Recurse into children
            for child in n.children:
                walk_for_strings(child)
        
        walk_for_strings(node)
        return literals
    
    def _extract_all_calls(self, node: Node) -> List[dict]:
        """Extract ALL function calls with their arguments.
        
        Let the LLM decide what's dangerous - no hardcoded patterns!
        
        Args:
            node: AST node to search
            
        Returns:
            List of dicts with call details
        """
        all_calls = []
        
        def extract_call(n: Node):
            if n.type == 'call':
                # Extract function name
                func_name = None
                args = []
                
                for child in n.children:
                    if child.type in ['identifier', 'constant']:
                        func_name = self.parser.get_node_text(child)
                        break
                
                # Extract arguments
                for child in n.children:
                    if child.type == 'argument_list':
                        for arg_child in child.children:
                            if arg_child.type != ',':
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
        """Extract all require/import statements.
        
        Returns:
            List of import statements
        """
        imports = []
        
        def find_imports(n: Node):
            if n.type == 'call' and n.children:
                first_child = n.children[0] if n.children else None
                if first_child and self.parser.get_node_text(first_child) in ['require', 'require_relative', 'load']:
                    import_text = self.parser.get_node_text(n)
                    if len(import_text) < 150:
                        imports.append(import_text)
            
            for child in n.children:
                find_imports(child)
        
        find_imports(node)
        return imports
    
    def _extract_assignments(self, node: Node) -> List[dict]:
        """Extract all variable assignments.
        
        Returns:
            List of assignment info
        """
        assignments = []
        
        def find_assignments(n: Node):
            if n.type == 'assignment':
                var_name = None
                value = None
                
                children = list(n.children)
                if len(children) >= 2:
                    var_name = self.parser.get_node_text(children[0])
                    value_text = self.parser.get_node_text(children[-1])
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
            if n.type in ['return', 'return_statement']:
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
        """Extract all begin-rescue-end blocks.
        
        Returns:
            List of exception handler info
        """
        handlers = []
        
        def find_handlers(n: Node):
            if n.type in ['begin', 'begin_block']:
                handler_info = {
                    'line': n.start_point[0] + 1,
                    'has_rescue': False,
                    'has_ensure': False,
                    'rescue_types': []
                }
                
                for child in n.children:
                    if child.type == 'rescue':
                        handler_info['has_rescue'] = True
                        # Try to get exception type
                        for rescue_child in child.children:
                            if rescue_child.type in ['constant', 'scope_resolution']:
                                exc_type = self.parser.get_node_text(rescue_child)
                                handler_info['rescue_types'].append(exc_type)
                    elif child.type == 'ensure':
                        handler_info['has_ensure'] = True
                
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
            if n.type in ['if', 'unless', 'case', 'conditional']:
                has_conditionals = True
            elif n.type in ['while', 'until', 'for']:
                has_loops = True
            elif n.type in ['begin', 'rescue']:
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
        """Extract environment variable accesses (ENV['X'])."""
        env_vars = []
        
        def find_env(n):
            if n.type == 'call':
                text = self.parser.get_node_text(n)
                if 'ENV[' in text:
                    # Try to extract the env var name
                    for child in n.children:
                        if child.type == 'argument_list':
                            for arg in child.children:
                                if arg.type in ['string', 'simple_symbol']:
                                    var_name = self.parser.get_node_text(arg).strip('"\':')
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
            if n.type == 'assignment':
                var_name = None
                deps = []
                for child in n.children:
                    if child.type in ['identifier', 'constant']:
                        var_name = self.parser.get_node_text(child)
                    else:
                        deps = extract_identifiers(child)
                if var_name and deps:
                    dependencies[var_name] = deps
            for child in n.children:
                find_deps(child)
        
        find_deps(node)
        return dependencies
