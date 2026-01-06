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

"""TypeScript Code Context Extractor for Static Analysis.

This module extracts comprehensive code context from TypeScript/JavaScript source
by traversing and analyzing tree-sitter ASTs. It provides:
- Extracts complete function context for MCP entry points
- Performs forward dataflow analysis from parameters
- Tracks taint flows to dangerous operations
- Collects constants, imports, and behavioral patterns

Classes:
    TypeScriptFunctionContext: Complete context for a TypeScript function
    TypeScriptContextExtractor: Main extractor for comprehensive TypeScript code analysis
"""

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from tree_sitter import Node

from .parser.typescript_parser import TypeScriptParser


@dataclass
class TypeScriptFunctionContext:
    """Complete context for a TypeScript function."""
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


class TypeScriptContextExtractor:
    """Extracts comprehensive code context by analyzing TypeScript tree-sitter ASTs.
    
    This class traverses TypeScript ASTs to extract rich context information including
    dataflow, taint tracking, and behavioral patterns for security analysis.
    """
    
    # Configurable security pattern lists
    DEFAULT_FILE_PATTERNS = ["readfile", "writefile", "readfilesync", "writefilesync", 
                            "createreadstream", "createwritestream", "unlink", "rmdir",
                            "mkdir", "rename", "copyfile", "fs.", "path."]
    DEFAULT_NETWORK_PATTERNS = ["fetch", "axios", "http.", "https.", "request", 
                               "xmlhttprequest", "websocket", "socket.", "net."]
    DEFAULT_SUBPROCESS_PATTERNS = ["exec", "spawn", "execsync", "spawnsync", 
                                   "child_process", "execfile", "fork"]
    
    # MCP SDK patterns for detecting tool/resource/prompt registrations
    MCP_PATTERNS = [
        'registerTool', 'server.tool', 'mcp.tool',
        'registerResource', 'server.resource', 'mcp.resource', 
        'registerPrompt', 'server.prompt', 'mcp.prompt',
        'setRequestHandler', 'addTool', 'addResource', 'addPrompt'
    ]

    def __init__(
        self, 
        source_code: str, 
        file_path: str = "unknown.ts",
        file_patterns: List[str] = None,
        network_patterns: List[str] = None,
        subprocess_patterns: List[str] = None
    ):
        """Initialize TypeScript context extractor.

        Args:
            source_code: TypeScript source code
            file_path: Path to source file
            file_patterns: Custom file operation patterns
            network_patterns: Custom network operation patterns
            subprocess_patterns: Custom subprocess patterns
        """
        self.source_code = source_code
        self.file_path = Path(file_path)
        self.logger = logging.getLogger(__name__)
        
        # Determine if TSX based on file extension
        is_tsx = str(file_path).endswith('.tsx')
        self.parser = TypeScriptParser(self.file_path, source_code, is_tsx=is_tsx)
        
        # Use provided patterns or defaults
        self.file_patterns = [p.lower() for p in (file_patterns or self.DEFAULT_FILE_PATTERNS)]
        self.network_patterns = [p.lower() for p in (network_patterns or self.DEFAULT_NETWORK_PATTERNS)]
        self.subprocess_patterns = [p.lower() for p in (subprocess_patterns or self.DEFAULT_SUBPROCESS_PATTERNS)]
        
        # Parse the source
        try:
            self.tree = self.parser.parse()
            self.root = self.tree.root_node
        except SyntaxError as e:
            raise ValueError(f"Failed to parse TypeScript source code: {e}")

    def extract_mcp_function_contexts(self) -> List[TypeScriptFunctionContext]:
        """Extract contexts for all MCP-related functions.

        Returns:
            List of function contexts
        """
        contexts = []
        
        # Find all function definitions
        for node in self.parser.walk(self.root):
            if node.type in {'function_declaration', 'arrow_function', 'function_expression', 'method_definition'}:
                # Check if this is an MCP handler
                mcp_type = self._get_mcp_type(node)
                if mcp_type:
                    context = self._extract_function_context(node, mcp_type)
                    contexts.append(context)
        
        # Also look for registerTool/setRequestHandler/etc. call patterns
        for call_node in self.parser.get_function_calls(self.root):
            call_name = self.parser.get_call_name(call_node)
            if any(pattern in call_name.lower() for pattern in [
                'registertool', 'registerresource', 'registerprompt', 
                'server.tool', 'mcp.tool', 'setrequesthandler', 'addtool',
                'addresource', 'addprompt', 'server.setRequestHandler'
            ]):
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
        # Check for decorators (TypeScript experimental decorators)
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

    def _extract_mcp_registration_context(self, call_node: Node) -> Optional[TypeScriptFunctionContext]:
        """Extract context from an MCP registration call like server.registerTool().

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
                if child.type == 'arguments':
                    args_node = child
                    break
        
        if not args_node:
            return None
        
        # Extract tool name and handler from arguments
        tool_name = ''
        handler_node = None
        config_node = None
        
        for i, child in enumerate(args_node.children):
            if child.type in {'string', 'template_string'}:
                tool_name = self.parser.get_node_text(child).strip('"\'`')
            elif child.type == 'object':
                config_node = child
            elif child.type in {'arrow_function', 'function_expression', 'identifier'}:
                handler_node = child
        
        # If handler is an identifier, try to find the actual function
        if handler_node and handler_node.type == 'identifier':
            handler_name = self.parser.get_node_text(handler_node)
            for func in self.parser.get_function_defs(self.root):
                if self.parser.get_function_name(func) == handler_name:
                    handler_node = func
                    break
        
        if not handler_node:
            return None
        
        # Extract context from the handler
        context = self._extract_function_context(handler_node, mcp_type)
        
        # Try to extract a more specific tool name from the handler body
        # Look for patterns like: if (name === "tool_name") or if (name === 'tool_name')
        inner_tool_name = self._extract_tool_name_from_handler(handler_node)
        
        # Override name - prefer inner tool name, then explicit tool_name, then default
        if inner_tool_name:
            context.name = inner_tool_name
        elif tool_name:
            context.name = tool_name
        
        # Extract config parameters if present
        if config_node:
            context.decorator_params = self._extract_object_properties(config_node)
        
        return context

    def _extract_tool_name_from_handler(self, handler_node: Node) -> Optional[str]:
        """Extract tool name from handler body by looking for if (name === "tool_name") patterns.

        Args:
            handler_node: The handler function node

        Returns:
            Tool name if found, None otherwise
        """
        for child in self.parser.walk(handler_node):
            # Look for binary expressions with === or ==
            if child.type == 'binary_expression':
                operator = None
                left_text = ''
                right_text = ''
                
                for subchild in child.children:
                    if subchild.type in {'===', '==', '!==', '!='}:
                        operator = subchild.type
                    elif subchild.type == 'identifier':
                        text = self.parser.get_node_text(subchild)
                        if not left_text:
                            left_text = text
                        else:
                            right_text = text
                    elif subchild.type in {'string', 'template_string'}:
                        right_text = self.parser.get_node_text(subchild).strip('"\'`')
                
                # Check if this is a name comparison like: name === "tool_name"
                if operator in {'===', '=='} and left_text == 'name' and right_text:
                    return right_text
        
        return None

    def _extract_function_context(self, node: Node, mcp_type: str) -> TypeScriptFunctionContext:
        """Extract complete context for a function.

        Args:
            node: Function definition node
            mcp_type: MCP type (tool, resource, prompt)

        Returns:
            Function context
        """
        # Basic info
        name = self.parser.get_function_name(node) or '<anonymous>'
        docstring = self.parser.get_docstring(node)
        parameters = self.parser.get_function_parameters(node)
        return_type = self.parser.get_return_type(node)
        line_number = node.start_point[0] + 1
        
        # Decorators
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
        
        return TypeScriptFunctionContext(
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
            if assign_node.type in {'variable_declaration', 'lexical_declaration'}:
                # Handle const/let/var declarations
                for child in assign_node.children:
                    if child.type == 'variable_declarator':
                        name_node = child.child_by_field_name('name')
                        value_node = child.child_by_field_name('value')
                        
                        if name_node:
                            assignments.append({
                                'variable': self.parser.get_node_text(name_node),
                                'value': self.parser.get_node_text(value_node) if value_node else '<no value>',
                                'line': assign_node.start_point[0] + 1,
                                'type': 'declaration',
                            })
            
            elif assign_node.type == 'assignment_expression':
                left = assign_node.child_by_field_name('left')
                right = assign_node.child_by_field_name('right')
                
                if left:
                    assignments.append({
                        'variable': self.parser.get_node_text(left),
                        'value': self.parser.get_node_text(right) if right else '<no value>',
                        'line': assign_node.start_point[0] + 1,
                        'type': 'assignment',
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
        has_while = False
        has_try = False
        has_switch = False
        
        for child in self.parser.walk(node):
            if child.type == 'if_statement':
                has_if = True
            elif child.type in {'for_statement', 'for_in_statement', 'for_of_statement'}:
                has_for = True
            elif child.type in {'while_statement', 'do_statement'}:
                has_while = True
            elif child.type == 'try_statement':
                has_try = True
            elif child.type == 'switch_statement':
                has_switch = True
        
        return {
            'has_conditionals': has_if or has_switch,
            'has_loops': has_for or has_while,
            'has_exception_handling': has_try,
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
                        
                        elif parent.type in {'assignment_expression', 'variable_declarator'}:
                            flow['reaches_assignments'].append(self.parser.get_node_text(parent))
                        
                        elif parent.type == 'return_statement':
                            flow['reaches_returns'] = True
                        
                        elif parent.type == 'member_expression':
                            flow['operations'].append({
                                'type': 'property_access',
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
            if child.type == 'lexical_declaration':
                # Check if it's a const declaration
                for subchild in child.children:
                    if subchild.type == 'const':
                        # Extract variable declarators
                        for declarator in child.children:
                            if declarator.type == 'variable_declarator':
                                name_node = declarator.child_by_field_name('name')
                                value_node = declarator.child_by_field_name('value')
                                
                                if name_node and value_node:
                                    name = self.parser.get_node_text(name_node)
                                    
                                    # Only extract simple constant values
                                    if value_node.type in {'string', 'number', 'true', 'false', 'null'}:
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
            if assign.type == 'variable_declarator':
                name_node = assign.child_by_field_name('name')
                value_node = assign.child_by_field_name('value')
                
                if name_node and value_node:
                    var_name = self.parser.get_node_text(name_node)
                    deps = []
                    
                    for child in self.parser.walk(value_node):
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
        """Check for eval/exec calls.

        Args:
            node: Function node

        Returns:
            True if eval/exec detected
        """
        dangerous_funcs = {'eval', 'function', 'settimeout', 'setinterval'}
        
        for call in self.parser.get_function_calls(node):
            call_name = self.parser.get_call_name(call).lower()
            if call_name in dangerous_funcs:
                return True
            # Check for new Function() pattern
            if 'function' in call_name:
                return True
        
        return False

    def _has_dangerous_imports(self) -> bool:
        """Check for dangerous imports.

        Returns:
            True if dangerous imports detected
        """
        dangerous_modules = {'child_process', 'vm', 'eval'}
        
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
            if child.type in {'string', 'template_string'}:
                text = self.parser.get_node_text(child)
                # Remove quotes
                if text.startswith('"') or text.startswith("'"):
                    text = text[1:-1]
                elif text.startswith('`'):
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
                # Get the return value
                for subchild in child.children:
                    if subchild.type not in {'return', ';'}:
                        returns.append(self.parser.get_node_text(subchild))
        
        return returns

    def _extract_exception_handlers(self, node: Node) -> List[Dict[str, Any]]:
        """Extract exception handlers from function.

        Args:
            node: Function node

        Returns:
            List of exception handler info
        """
        handlers = []
        
        for child in self.parser.walk(node):
            if child.type == 'catch_clause':
                handler_info = {
                    'line': child.start_point[0] + 1,
                    'parameter': '',
                    'exception_type': 'Error',  # TypeScript catch is generic
                    'is_silent': False,
                    'body_preview': '',
                }
                
                # Get catch parameter
                param = child.child_by_field_name('parameter')
                if param:
                    handler_info['parameter'] = self.parser.get_node_text(param)
                
                # Get body preview
                body = child.child_by_field_name('body')
                if body:
                    body_text = self.parser.get_node_text(body)
                    handler_info['body_preview'] = body_text[:100]
                    # Check if it's a silent catch (empty or just comments)
                    handler_info['is_silent'] = body_text.strip() in {'{}', '{ }', ''}
                
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
        
        for child in self.parser.walk(node):
            if child.type == 'member_expression':
                text = self.parser.get_node_text(child)
                if 'process.env' in text:
                    # Extract the env var name
                    parts = text.split('.')
                    if len(parts) >= 3:
                        env_vars.append(parts[2])
        
        return env_vars

    def _extract_global_writes(self, node: Node) -> List[Dict[str, Any]]:
        """Extract global variable writes.

        Args:
            node: Function node

        Returns:
            List of global write info
        """
        writes = []
        
        # Look for assignments to global-looking variables
        for child in self.parser.walk(node):
            if child.type == 'assignment_expression':
                left = child.child_by_field_name('left')
                if left and left.type == 'member_expression':
                    text = self.parser.get_node_text(left)
                    if text.startswith('global.') or text.startswith('window.'):
                        writes.append({
                            'target': text,
                            'line': child.start_point[0] + 1,
                        })
        
        return writes

    def _extract_attribute_access(self, node: Node) -> List[Dict[str, Any]]:
        """Extract attribute/property accesses.

        Args:
            node: Function node

        Returns:
            List of attribute access info
        """
        accesses = []
        
        for child in self.parser.walk(node):
            if child.type == 'member_expression':
                obj = child.child_by_field_name('object')
                prop = child.child_by_field_name('property')
                
                if obj and prop:
                    # Determine if this is a read or write based on parent context
                    parent = child.parent
                    is_write = parent and parent.type in {'assignment_expression', 'augmented_assignment_expression'}
                    
                    accesses.append({
                        'object': self.parser.get_node_text(obj),
                        'property': self.parser.get_node_text(prop),
                        'attribute': self.parser.get_node_text(prop),  # Alias for compatibility
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
            if child.type in {'if_statement', 'for_statement', 'for_in_statement', 
                             'for_of_statement', 'while_statement', 'do_statement',
                             'catch_clause', 'switch_case'}:
                complexity += 1
            elif child.type == 'ternary_expression':
                complexity += 1
            elif child.type == 'binary_expression':
                # Check for && or ||
                op = child.child_by_field_name('operator')
                if op:
                    op_text = self.parser.get_node_text(op)
                    if op_text in {'&&', '||'}:
                        complexity += 1
        
        return complexity

    def _extract_object_properties(self, node: Node) -> Dict[str, Any]:
        """Extract properties from an object literal.

        Args:
            node: Object node

        Returns:
            Dictionary of properties
        """
        props = {}
        
        for child in node.children:
            if child.type == 'pair':
                key = child.child_by_field_name('key')
                value = child.child_by_field_name('value')
                
                if key and value:
                    key_text = self.parser.get_node_text(key).strip('"\'')
                    
                    # Extract simple values
                    if value.type in {'string', 'number', 'true', 'false', 'null'}:
                        props[key_text] = self.parser.get_node_text(value).strip('"\'')
                    else:
                        props[key_text] = self.parser.get_node_text(value)
        
        return props
