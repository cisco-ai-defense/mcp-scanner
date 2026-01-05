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

"""Go Code Context Extractor for Static Analysis.

This module extracts comprehensive code context from Go source
by traversing and analyzing tree-sitter ASTs. It provides:
- Extracts complete function context for MCP entry points
- Performs forward dataflow analysis from parameters
- Tracks taint flows to dangerous operations
- Collects constants, imports, and behavioral patterns

Classes:
    GoFunctionContext: Complete context for a Go function
    GoContextExtractor: Main extractor for comprehensive Go code analysis
"""

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from tree_sitter import Node

from .parser.go_parser import GoParser


@dataclass
class GoFunctionContext:
    """Complete context for a Go function."""
    # Required fields (no defaults)
    name: str
    decorator_types: List[str]
    imports: List[str]
    function_calls: List[Dict[str, Any]]
    assignments: List[Dict[str, Any]]
    control_flow: Dict[str, Any]
    parameter_flows: List[Dict[str, Any]]
    constants: Dict[str, Any]
    variable_dependencies: Dict[str, List[str]]
    has_file_operations: bool
    has_network_operations: bool
    has_subprocess_calls: bool
    has_eval_exec: bool
    has_dangerous_imports: bool
    
    # Optional fields (with defaults)
    decorator_params: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    docstring: Optional[str] = None
    parameters: List[Dict[str, Any]] = field(default_factory=list)
    return_type: Optional[str] = None
    line_number: int = 0
    
    # Cross-file analysis
    cross_file_calls: List[Dict[str, Any]] = field(default_factory=list)
    reachable_functions: List[str] = field(default_factory=list)
    
    # High-value security indicators
    string_literals: List[str] = field(default_factory=list)
    return_expressions: List[str] = field(default_factory=list)
    exception_handlers: List[Dict[str, Any]] = field(default_factory=list)
    env_var_access: List[str] = field(default_factory=list)
    
    # State manipulation
    global_writes: List[Dict[str, Any]] = field(default_factory=list)
    attribute_access: List[Dict[str, Any]] = field(default_factory=list)
    
    # Dataflow facts
    dataflow_summary: Dict[str, Any] = field(default_factory=dict)


class GoContextExtractor:
    """Extracts comprehensive code context by analyzing Go tree-sitter ASTs.
    
    This class traverses Go ASTs to extract rich context information including
    dataflow, taint tracking, and behavioral patterns for security analysis.
    """
    
    # Configurable security pattern lists
    DEFAULT_FILE_PATTERNS = ["ioutil.readfile", "ioutil.writefile", "os.open", "os.create",
                            "os.readfile", "os.writefile", "os.remove", "os.rename",
                            "os.mkdir", "os.mkdirall", "filepath.", "bufio."]
    DEFAULT_NETWORK_PATTERNS = ["http.get", "http.post", "http.newrequest", "http.client",
                               "net.dial", "net.listen", "grpc.", "websocket."]
    DEFAULT_SUBPROCESS_PATTERNS = ["exec.command", "os.exec", "syscall.exec", "os/exec"]
    
    # MCP SDK patterns for detecting tool/resource/prompt registrations (mcp-go)
    MCP_PATTERNS = [
        'AddTool', 'server.AddTool', 'mcp.NewTool',
        'AddResource', 'server.AddResource', 'mcp.NewResource',
        'AddPrompt', 'server.AddPrompt', 'mcp.NewPrompt',
        'SetRequestHandler', 'server.tool', 'server.resource', 'server.prompt'
    ]

    def __init__(
        self, 
        source_code: str, 
        file_path: str = "unknown.go",
        file_patterns: List[str] = None,
        network_patterns: List[str] = None,
        subprocess_patterns: List[str] = None
    ):
        """Initialize Go context extractor.

        Args:
            source_code: Go source code
            file_path: Path to source file
            file_patterns: Custom file operation patterns
            network_patterns: Custom network operation patterns
            subprocess_patterns: Custom subprocess patterns
        """
        self.source_code = source_code
        self.file_path = Path(file_path)
        self.logger = logging.getLogger(__name__)
        
        self.parser = GoParser(self.file_path, source_code)
        
        # Use provided patterns or defaults
        self.file_patterns = [p.lower() for p in (file_patterns or self.DEFAULT_FILE_PATTERNS)]
        self.network_patterns = [p.lower() for p in (network_patterns or self.DEFAULT_NETWORK_PATTERNS)]
        self.subprocess_patterns = [p.lower() for p in (subprocess_patterns or self.DEFAULT_SUBPROCESS_PATTERNS)]
        
        # Parse the source
        try:
            self.tree = self.parser.parse()
            self.root = self.tree.root_node
        except SyntaxError as e:
            raise ValueError(f"Failed to parse Go source code: {e}")

    def extract_mcp_function_contexts(self) -> List[GoFunctionContext]:
        """Extract contexts for all MCP-related functions.

        Returns:
            List of function contexts
        """
        contexts = []
        
        # Find all function definitions
        for node in self.parser.walk(self.root):
            if node.type in {'function_declaration', 'method_declaration'}:
                # Check if this is an MCP handler
                mcp_type = self._get_mcp_type(node)
                if mcp_type:
                    context = self._extract_function_context(node, mcp_type)
                    contexts.append(context)
        
        # Also look for AddTool/etc. call patterns
        for call_node in self.parser.get_function_calls(self.root):
            call_name = self.parser.get_call_name(call_node)
            if any(pattern.lower() in call_name.lower() for pattern in ['addtool', 'addresource', 'addprompt', 'newtool']):
                # Extract the handler function from the call arguments
                handler_context = self._extract_mcp_registration_context(call_node)
                if handler_context:
                    contexts.append(handler_context)
        
        return contexts

    def _get_mcp_type(self, node: Node) -> Optional[str]:
        """Determine if a function is an MCP handler and return its type.

        Args:
            node: Function definition node

        Returns:
            MCP type ('tool', 'resource', 'prompt') or None
        """
        func_name = self.parser.get_function_name(node).lower()
        
        # Check function name patterns
        if 'handler' in func_name:
            if 'tool' in func_name:
                return 'tool'
            if 'resource' in func_name:
                return 'resource'
            if 'prompt' in func_name:
                return 'prompt'
        
        # Check for comment annotations (Go uses comments for annotations)
        decorators = self.parser.get_decorators(node)
        for dec in decorators:
            dec_text = self.parser.get_node_text(dec).lower()
            if 'tool' in dec_text:
                return 'tool'
            if 'resource' in dec_text:
                return 'resource'
            if 'prompt' in dec_text:
                return 'prompt'
        
        # Check parent context - is this passed to a registration call?
        parent = node.parent
        while parent:
            if parent.type == 'call_expression':
                call_name = self.parser.get_call_name(parent).lower()
                if 'tool' in call_name:
                    return 'tool'
                if 'resource' in call_name:
                    return 'resource'
                if 'prompt' in call_name:
                    return 'prompt'
            parent = parent.parent
        
        return None

    def _extract_mcp_registration_context(self, call_node: Node) -> Optional[GoFunctionContext]:
        """Extract context from an MCP registration call like s.AddTool().

        Args:
            call_node: The call_expression node

        Returns:
            Function context or None
        """
        call_name = self.parser.get_call_name(call_node)
        
        # Determine MCP type
        mcp_type = 'tool'
        if 'resource' in call_name.lower():
            mcp_type = 'resource'
        elif 'prompt' in call_name.lower():
            mcp_type = 'prompt'
        
        # Find the arguments node
        args_node = call_node.child_by_field_name('arguments')
        if not args_node:
            for child in call_node.children:
                if child.type == 'argument_list':
                    args_node = child
                    break
        
        if not args_node:
            return None
        
        # Extract tool name and handler from arguments
        tool_name = ''
        handler_node = None
        
        for child in args_node.children:
            if child.type == 'interpreted_string_literal':
                tool_name = self.parser.get_node_text(child).strip('"')
            elif child.type == 'identifier':
                # This might be a handler function reference
                handler_name = self.parser.get_node_text(child)
                for func in self.parser.get_function_defs(self.root):
                    if self.parser.get_function_name(func) == handler_name:
                        handler_node = func
                        break
            elif child.type == 'func_literal':
                handler_node = child
        
        if not handler_node:
            # Create a context from the call itself
            return self._create_context_from_call(call_node, tool_name, mcp_type)
        
        # Extract context from the handler
        context = self._extract_function_context(handler_node, mcp_type)
        
        # Override name if explicitly provided
        if tool_name:
            context.name = tool_name
        
        return context

    def _create_context_from_call(self, call_node: Node, tool_name: str, mcp_type: str) -> GoFunctionContext:
        """Create a context from an MCP registration call when handler is inline or not found.

        Args:
            call_node: The call_expression node
            tool_name: Tool name
            mcp_type: MCP type

        Returns:
            Function context
        """
        # Extract what we can from the call context
        imports = self._extract_imports()
        function_calls = self._extract_function_calls(call_node)
        
        return GoFunctionContext(
            name=tool_name or '<unknown>',
            decorator_types=[mcp_type],
            decorator_params={},
            docstring=None,
            parameters=[],
            return_type=None,
            line_number=call_node.start_point[0] + 1,
            imports=imports,
            function_calls=function_calls,
            assignments=[],
            control_flow={'has_conditionals': False, 'has_loops': False, 'has_exception_handling': False},
            parameter_flows=[],
            constants={},
            variable_dependencies={},
            has_file_operations=False,
            has_network_operations=False,
            has_subprocess_calls=False,
            has_eval_exec=False,
            has_dangerous_imports=self._has_dangerous_imports(),
            dataflow_summary={'total_statements': 0, 'total_expressions': 0, 'complexity': 1},
            string_literals=[],
            return_expressions=[],
            exception_handlers=[],
            env_var_access=[],
            global_writes=[],
            attribute_access=[],
        )

    def _extract_function_context(self, node: Node, mcp_type: str) -> GoFunctionContext:
        """Extract complete context for a function.

        Args:
            node: Function definition node
            mcp_type: MCP type (tool, resource, prompt)

        Returns:
            Function context
        """
        # Basic info
        name = self.parser.get_function_name(node) or '<anonymous>'
        docstring = self._get_docstring(node)
        parameters = self.parser.get_function_parameters(node)
        return_type = self._get_return_type(node)
        line_number = node.start_point[0] + 1
        
        # Decorators (Go uses comments)
        decorators = self.parser.get_decorators(node)
        decorator_types = [self.parser.get_node_text(d) for d in decorators]
        
        # Code structure
        imports = self._extract_imports()
        function_calls = self._extract_function_calls(node)
        assignments = self._extract_assignments(node)
        control_flow = self._analyze_control_flow(node)
        
        # Parameter flows
        parameter_flows = self._analyze_parameter_flows(node, parameters)
        
        # Constants
        constants = self._extract_constants(node)
        
        # Variable dependencies
        var_deps = self._analyze_variable_dependencies(node)
        
        # Behavioral patterns
        has_file_ops = self._has_file_operations(node)
        has_network_ops = self._has_network_operations(node)
        has_subprocess = self._has_subprocess_calls(node)
        has_eval_exec = self._has_eval_exec(node)
        has_dangerous_imports = self._has_dangerous_imports()
        
        # High-value security indicators
        string_literals = self._extract_string_literals(node)
        return_expressions = self._extract_return_expressions(node)
        exception_handlers = self._extract_exception_handlers(node)
        env_var_access = self._extract_env_var_access(node)
        
        # State manipulation
        global_writes = self._extract_global_writes(node)
        attribute_access = self._extract_attribute_access(node)
        
        # Dataflow summary
        dataflow_summary = self._create_dataflow_summary(node)
        
        return GoFunctionContext(
            name=name,
            decorator_types=decorator_types,
            decorator_params={},
            docstring=docstring,
            parameters=parameters,
            return_type=return_type,
            line_number=line_number,
            imports=imports,
            function_calls=function_calls,
            assignments=assignments,
            control_flow=control_flow,
            parameter_flows=parameter_flows,
            constants=constants,
            variable_dependencies=var_deps,
            has_file_operations=has_file_ops,
            has_network_operations=has_network_ops,
            has_subprocess_calls=has_subprocess,
            has_eval_exec=has_eval_exec,
            has_dangerous_imports=has_dangerous_imports,
            dataflow_summary=dataflow_summary,
            string_literals=string_literals,
            return_expressions=return_expressions,
            exception_handlers=exception_handlers,
            env_var_access=env_var_access,
            global_writes=global_writes,
            attribute_access=attribute_access,
        )

    def _get_docstring(self, node: Node) -> Optional[str]:
        """Get docstring/comment for a function.

        Args:
            node: Function node

        Returns:
            Docstring or None
        """
        # In Go, documentation is in comments preceding the function
        prev = node.prev_sibling
        comments = []
        
        while prev and prev.type == 'comment':
            comment_text = self.parser.get_node_text(prev)
            # Remove // prefix
            if comment_text.startswith('//'):
                comment_text = comment_text[2:].strip()
            comments.insert(0, comment_text)
            prev = prev.prev_sibling
        
        return '\n'.join(comments) if comments else None

    def _get_return_type(self, node: Node) -> Optional[str]:
        """Get return type of a function.

        Args:
            node: Function node

        Returns:
            Return type or None
        """
        result = node.child_by_field_name('result')
        if result:
            return self.parser.get_node_text(result)
        return None

    def _extract_imports(self) -> List[str]:
        """Extract all imports from the file.

        Returns:
            List of import statements
        """
        imports = []
        for node in self.parser.get_imports(self.root):
            import_text = self.parser.get_node_text(node)
            if import_text not in imports:
                imports.append(import_text)
        return imports

    def _extract_function_calls(self, node: Node) -> List[Dict[str, Any]]:
        """Extract all function calls within a node.

        Args:
            node: AST node

        Returns:
            List of function call info
        """
        calls = []
        for call_node in self.parser.get_function_calls(node):
            call_name = self.parser.get_call_name(call_node)
            
            # Extract arguments
            args = []
            args_node = call_node.child_by_field_name('arguments')
            if args_node:
                for child in args_node.children:
                    if child.type not in {'(', ')', ','}:
                        args.append(self.parser.get_node_text(child))
            
            calls.append({
                'name': call_name,
                'args': args,
                'line': call_node.start_point[0] + 1,
            })
        
        return calls

    def _extract_assignments(self, node: Node) -> List[Dict[str, Any]]:
        """Extract all assignments within a node.

        Args:
            node: AST node

        Returns:
            List of assignment info
        """
        assignments = []
        
        for assign_node in self.parser.get_assignments(node):
            if assign_node.type == 'short_var_declaration':
                # Handle := declarations
                left = assign_node.child_by_field_name('left')
                right = assign_node.child_by_field_name('right')
                
                if left:
                    assignments.append({
                        'variable': self.parser.get_node_text(left),
                        'value': self.parser.get_node_text(right) if right else '<no value>',
                        'line': assign_node.start_point[0] + 1,
                        'type': 'short_var',
                    })
            
            elif assign_node.type == 'assignment_statement':
                left = assign_node.child_by_field_name('left')
                right = assign_node.child_by_field_name('right')
                
                if left:
                    assignments.append({
                        'variable': self.parser.get_node_text(left),
                        'value': self.parser.get_node_text(right) if right else '<no value>',
                        'line': assign_node.start_point[0] + 1,
                        'type': 'assignment',
                    })
            
            elif assign_node.type == 'var_declaration':
                # Handle var declarations
                for child in assign_node.children:
                    if child.type == 'var_spec':
                        name_node = child.child_by_field_name('name')
                        value_node = child.child_by_field_name('value')
                        
                        if name_node:
                            assignments.append({
                                'variable': self.parser.get_node_text(name_node),
                                'value': self.parser.get_node_text(value_node) if value_node else '<no value>',
                                'line': assign_node.start_point[0] + 1,
                                'type': 'var_declaration',
                            })
        
        return assignments

    def _analyze_control_flow(self, node: Node) -> Dict[str, Any]:
        """Analyze control flow structure.

        Args:
            node: Function node

        Returns:
            Control flow summary
        """
        has_if = False
        has_for = False
        has_switch = False
        has_defer = False
        
        for child in self.parser.walk(node):
            if child.type == 'if_statement':
                has_if = True
            elif child.type in {'for_statement', 'range_statement'}:
                has_for = True
            elif child.type in {'switch_statement', 'type_switch_statement', 'select_statement'}:
                has_switch = True
            elif child.type == 'defer_statement':
                has_defer = True
        
        return {
            'has_conditionals': has_if or has_switch,
            'has_loops': has_for,
            'has_exception_handling': has_defer,  # Go uses defer for cleanup
            'has_switch': has_switch,
        }

    def _analyze_parameter_flows(self, node: Node, parameters: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze how parameters flow through the function.

        Args:
            node: Function node
            parameters: List of parameter info

        Returns:
            List of parameter flow info
        """
        flows = []
        param_names = {p.get('name', '') for p in parameters}
        
        for param in parameters:
            param_name = param.get('name', '')
            if not param_name:
                continue
            
            flow = {
                'parameter': param_name,
                'operations': [],
                'reaches_calls': [],
                'reaches_assignments': [],
                'reaches_returns': False,
                'reaches_external': False,
            }
            
            # Track where this parameter is used
            for child in self.parser.walk(node):
                if child.type == 'identifier' and self.parser.get_node_text(child) == param_name:
                    parent = child.parent
                    if parent:
                        if parent.type == 'call_expression':
                            call_name = self.parser.get_call_name(parent)
                            flow['reaches_calls'].append(call_name)
                            
                            # Check if it reaches external operations
                            call_lower = call_name.lower()
                            if any(p in call_lower for p in self.network_patterns + self.subprocess_patterns):
                                flow['reaches_external'] = True
                        
                        elif parent.type in {'assignment_statement', 'short_var_declaration'}:
                            flow['reaches_assignments'].append(self.parser.get_node_text(parent))
                        
                        elif parent.type == 'return_statement':
                            flow['reaches_returns'] = True
                        
                        elif parent.type == 'selector_expression':
                            flow['operations'].append({
                                'type': 'field_access',
                                'line': child.start_point[0] + 1,
                                'target': self.parser.get_node_text(parent),
                                'value': param_name,
                            })
            
            flows.append(flow)
        
        return flows

    def _extract_constants(self, node: Node) -> Dict[str, Any]:
        """Extract constant values from the function.

        Args:
            node: Function node

        Returns:
            Dictionary of constants
        """
        constants = {}
        
        for child in self.parser.walk(node):
            if child.type == 'const_declaration':
                for spec in child.children:
                    if spec.type == 'const_spec':
                        name_node = spec.child_by_field_name('name')
                        value_node = spec.child_by_field_name('value')
                        
                        if name_node and value_node:
                            name = self.parser.get_node_text(name_node)
                            if value_node.type in {'interpreted_string_literal', 'int_literal', 
                                                   'float_literal', 'true', 'false', 'nil'}:
                                constants[name] = self.parser.get_node_text(value_node)
        
        return constants

    def _analyze_variable_dependencies(self, node: Node) -> Dict[str, List[str]]:
        """Analyze variable dependencies.

        Args:
            node: Function node

        Returns:
            Dictionary mapping variables to their dependencies
        """
        dependencies: Dict[str, List[str]] = {}
        
        for assign in self.parser.get_assignments(node):
            if assign.type == 'short_var_declaration':
                left = assign.child_by_field_name('left')
                right = assign.child_by_field_name('right')
                
                if left and right:
                    var_name = self.parser.get_node_text(left)
                    deps = []
                    
                    for child in self.parser.walk(right):
                        if child.type == 'identifier':
                            deps.append(self.parser.get_node_text(child))
                    
                    dependencies[var_name] = deps
        
        return dependencies

    def _has_file_operations(self, node: Node) -> bool:
        """Check for file operations.

        Args:
            node: Function node

        Returns:
            True if file operations detected
        """
        for call in self.parser.get_function_calls(node):
            call_name = self.parser.get_call_name(call).lower()
            if any(pattern in call_name for pattern in self.file_patterns):
                return True
        return False

    def _has_network_operations(self, node: Node) -> bool:
        """Check for network operations.

        Args:
            node: Function node

        Returns:
            True if network operations detected
        """
        for call in self.parser.get_function_calls(node):
            call_name = self.parser.get_call_name(call).lower()
            if any(pattern in call_name for pattern in self.network_patterns):
                return True
        return False

    def _has_subprocess_calls(self, node: Node) -> bool:
        """Check for subprocess calls.

        Args:
            node: Function node

        Returns:
            True if subprocess calls detected
        """
        for call in self.parser.get_function_calls(node):
            call_name = self.parser.get_call_name(call).lower()
            if any(pattern in call_name for pattern in self.subprocess_patterns):
                return True
        return False

    def _has_eval_exec(self, node: Node) -> bool:
        """Check for dynamic code execution.

        Args:
            node: Function node

        Returns:
            True if dynamic execution detected
        """
        # Go doesn't have eval, but check for reflect-based dynamic calls
        dangerous_patterns = {'reflect.call', 'reflect.value', 'plugin.open'}
        
        for call in self.parser.get_function_calls(node):
            call_name = self.parser.get_call_name(call).lower()
            if any(p in call_name for p in dangerous_patterns):
                return True
        
        return False

    def _has_dangerous_imports(self) -> bool:
        """Check for dangerous imports.

        Returns:
            True if dangerous imports detected
        """
        dangerous_modules = {'os/exec', 'syscall', 'unsafe', 'reflect', 'plugin'}
        
        for import_node in self.parser.get_imports(self.root):
            import_text = self.parser.get_node_text(import_node).lower()
            if any(mod in import_text for mod in dangerous_modules):
                return True
        
        return False

    def _extract_string_literals(self, node: Node) -> List[str]:
        """Extract string literals from function.

        Args:
            node: Function node

        Returns:
            List of string literals
        """
        literals = []
        
        for child in self.parser.walk(node):
            if child.type in {'interpreted_string_literal', 'raw_string_literal'}:
                text = self.parser.get_node_text(child)
                # Remove quotes
                if text.startswith('"') or text.startswith('`'):
                    text = text[1:-1]
                
                # Limit length
                text = text[:200]
                if text and text not in literals:
                    literals.append(text)
        
        return literals[:20]

    def _extract_return_expressions(self, node: Node) -> List[str]:
        """Extract return expressions from function.

        Args:
            node: Function node

        Returns:
            List of return expression strings
        """
        returns = []
        
        for child in self.parser.walk(node):
            if child.type == 'return_statement':
                # Get the return values
                for subchild in child.children:
                    if subchild.type not in {'return'}:
                        returns.append(self.parser.get_node_text(subchild))
        
        return returns

    def _extract_exception_handlers(self, node: Node) -> List[Dict[str, Any]]:
        """Extract defer statements (Go's cleanup mechanism).

        Args:
            node: Function node

        Returns:
            List of defer statement info
        """
        handlers = []
        
        for child in self.parser.walk(node):
            if child.type == 'defer_statement':
                handler_info = {
                    'line': child.start_point[0] + 1,
                    'exception_type': 'defer',  # Go uses defer instead of try/except
                    'is_silent': False,
                    'body_preview': self.parser.get_node_text(child)[:100],
                }
                handlers.append(handler_info)
        
        return handlers

    def _extract_env_var_access(self, node: Node) -> List[str]:
        """Extract environment variable accesses.

        Args:
            node: Function node

        Returns:
            List of env var names accessed
        """
        env_vars = []
        
        for call in self.parser.get_function_calls(node):
            call_name = self.parser.get_call_name(call).lower()
            if 'os.getenv' in call_name or 'os.lookupenv' in call_name:
                # Extract the env var name from arguments
                args_node = call.child_by_field_name('arguments')
                if args_node:
                    for child in args_node.children:
                        if child.type == 'interpreted_string_literal':
                            env_vars.append(self.parser.get_node_text(child).strip('"'))
        
        return env_vars

    def _extract_global_writes(self, node: Node) -> List[Dict[str, Any]]:
        """Extract global variable writes.

        Args:
            node: Function node

        Returns:
            List of global write info
        """
        writes = []
        
        # In Go, global writes are typically to package-level variables
        # This is harder to detect without full scope analysis
        # For now, look for assignments to capitalized identifiers (exported)
        for child in self.parser.walk(node):
            if child.type == 'assignment_statement':
                left = child.child_by_field_name('left')
                if left and left.type == 'identifier':
                    var_name = self.parser.get_node_text(left)
                    # Check if it looks like a package-level variable
                    if var_name[0].isupper():
                        writes.append({
                            'target': var_name,
                            'line': child.start_point[0] + 1,
                        })
        
        return writes

    def _extract_attribute_access(self, node: Node) -> List[Dict[str, Any]]:
        """Extract field/method accesses.

        Args:
            node: Function node

        Returns:
            List of attribute access info
        """
        accesses = []
        
        for child in self.parser.walk(node):
            if child.type == 'selector_expression':
                operand = child.child_by_field_name('operand')
                field = child.child_by_field_name('field')
                
                if operand and field:
                    # Determine if this is a read or write based on parent context
                    parent = child.parent
                    is_write = parent and parent.type in {'assignment_statement', 'short_var_declaration'}
                    
                    accesses.append({
                        'object': self.parser.get_node_text(operand),
                        'attribute': self.parser.get_node_text(field),
                        'property': self.parser.get_node_text(field),  # Alias for compatibility
                        'line': child.start_point[0] + 1,
                        'type': 'write' if is_write else 'read',
                        'value': '<assigned>' if is_write else None,
                    })
        
        # Limit to avoid huge lists
        return accesses[:50]

    def _create_dataflow_summary(self, node: Node) -> Dict[str, Any]:
        """Create dataflow summary.

        Args:
            node: Function node

        Returns:
            Dataflow summary
        """
        statements = 0
        expressions = 0
        
        for child in self.parser.walk(node):
            if child.type.endswith('_statement'):
                statements += 1
            elif child.type.endswith('_expression'):
                expressions += 1
        
        return {
            'total_statements': statements,
            'total_expressions': expressions,
            'complexity': self._calculate_complexity(node),
        }

    def _calculate_complexity(self, node: Node) -> int:
        """Calculate cyclomatic complexity.

        Args:
            node: Function node

        Returns:
            Complexity score
        """
        complexity = 1
        
        for child in self.parser.walk(node):
            if child.type in {'if_statement', 'for_statement', 'range_statement',
                             'switch_statement', 'type_switch_statement', 'select_statement',
                             'case_clause', 'default_case'}:
                complexity += 1
            elif child.type == 'binary_expression':
                # Check for && or ||
                op_node = child.child_by_field_name('operator')
                if op_node:
                    op = self.parser.get_node_text(op_node)
                    if op in {'&&', '||'}:
                        complexity += 1
        
        return complexity

    def _extract_object_properties(self, node: Node) -> Dict[str, Any]:
        """Extract properties from a struct literal.

        Args:
            node: Struct literal node

        Returns:
            Dictionary of properties
        """
        props = {}
        
        for child in self.parser.walk(node):
            if child.type == 'keyed_element':
                key_node = child.child_by_field_name('key')
                value_node = child.child_by_field_name('value')
                
                if key_node and value_node:
                    key = self.parser.get_node_text(key_node)
                    value = self.parser.get_node_text(value_node)
                    props[key] = value
        
        return props
