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

"""Kotlin Code Context Extractor for Static Analysis.

This module extracts comprehensive code context from Kotlin source
by traversing and analyzing tree-sitter ASTs. It provides:
- Extracts complete function context for MCP entry points
- Performs forward dataflow analysis from parameters
- Tracks taint flows to dangerous operations
- Collects constants, imports, and behavioral patterns

Classes:
    KotlinFunctionContext: Complete context for a Kotlin function
    KotlinContextExtractor: Main extractor for comprehensive Kotlin code analysis
"""

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from tree_sitter import Node

from .parser.kotlin_parser import KotlinParser


@dataclass
class KotlinFunctionContext:
    """Complete context for a Kotlin function."""
    # Required fields (no defaults)
    name: str
    annotation_types: List[str]
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
    annotation_params: Dict[str, Dict[str, Any]] = field(default_factory=dict)
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
    
    # State manipulation
    global_writes: List[Dict[str, Any]] = field(default_factory=list)
    property_access: List[Dict[str, Any]] = field(default_factory=list)
    
    # Dataflow facts
    dataflow_summary: Dict[str, Any] = field(default_factory=dict)


class KotlinContextExtractor:
    """Extracts comprehensive code context by analyzing Kotlin tree-sitter ASTs.
    
    This class traverses Kotlin ASTs to extract rich context information including
    dataflow, taint tracking, and behavioral patterns for security analysis.
    """
    
    # Configurable security pattern lists
    DEFAULT_FILE_PATTERNS = ["readfile", "writefile", "file", "inputstream", "outputstream",
                            "bufferedreader", "bufferedwriter", "filereader", "filewriter",
                            "path", "files.", "java.io", "java.nio"]
    DEFAULT_NETWORK_PATTERNS = ["http", "https", "socket", "url", "okhttp", "retrofit",
                               "ktor", "webclient", "httpurlconnection", "fetch"]
    DEFAULT_SUBPROCESS_PATTERNS = ["runtime.exec", "processbuilder", "process", 
                                   "shell", "command", "exec"]
    
    # MCP SDK patterns for detecting tool/resource/prompt registrations
    MCP_PATTERNS = [
        'addTool', 'addResource', 'addPrompt',
        'server.addTool', 'server.addResource', 'server.addPrompt',
        'registerTool', 'registerResource', 'registerPrompt',
    ]

    def __init__(
        self, 
        source_code: str, 
        file_path: str = "unknown.kt",
        file_patterns: List[str] = None,
        network_patterns: List[str] = None,
        subprocess_patterns: List[str] = None
    ):
        """Initialize Kotlin context extractor.

        Args:
            source_code: Kotlin source code
            file_path: Path to source file
            file_patterns: Custom file operation patterns
            network_patterns: Custom network operation patterns
            subprocess_patterns: Custom subprocess patterns
        """
        self.source_code = source_code
        self.file_path = Path(file_path)
        self.logger = logging.getLogger(__name__)
        
        self.parser = KotlinParser(self.file_path, source_code)
        
        # Use provided patterns or defaults
        self.file_patterns = [p.lower() for p in (file_patterns or self.DEFAULT_FILE_PATTERNS)]
        self.network_patterns = [p.lower() for p in (network_patterns or self.DEFAULT_NETWORK_PATTERNS)]
        self.subprocess_patterns = [p.lower() for p in (subprocess_patterns or self.DEFAULT_SUBPROCESS_PATTERNS)]
        
        # Parse the source
        try:
            self.tree = self.parser.parse()
            self.root = self.tree.root_node
        except SyntaxError as e:
            raise ValueError(f"Failed to parse Kotlin source code: {e}")

    def extract_mcp_function_contexts(self) -> List[KotlinFunctionContext]:
        """Extract contexts for all MCP-related functions.

        Returns:
            List of function contexts
        """
        contexts = []
        
        # Find all function definitions
        for node in self.parser.walk(self.root):
            if node.type in {'function_declaration', 'anonymous_function', 'lambda_literal'}:
                # Check if this is an MCP handler
                mcp_type = self._get_mcp_type(node)
                if mcp_type:
                    context = self._extract_function_context(node, mcp_type)
                    contexts.append(context)
        
        # Also look for addTool/addResource/addPrompt call patterns
        for call_node in self.parser.get_function_calls(self.root):
            call_name = self.parser.get_call_name(call_node)
            if any(pattern in call_name.lower() for pattern in ['addtool', 'addresource', 'addprompt']):
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
        # Check for annotations
        annotations = self.parser.get_annotations(node)
        for ann in annotations:
            ann_text = self.parser.get_node_text(ann).lower()
            if 'tool' in ann_text:
                return 'tool'
            if 'resource' in ann_text:
                return 'resource'
            if 'prompt' in ann_text:
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

    def _extract_mcp_registration_context(self, call_node: Node) -> Optional[KotlinFunctionContext]:
        """Extract context from an MCP registration call like server.addTool().

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
        
        # Find the lambda/function argument
        handler_node = None
        tool_name = ''
        
        for child in self.parser.walk(call_node):
            if child.type == 'lambda_literal':
                handler_node = child
            elif child.type in {'string_literal', 'line_string_literal'}:
                text = self.parser.get_node_text(child)
                if text.startswith('"'):
                    tool_name = text[1:-1]
        
        if not handler_node:
            return None
        
        # Extract context from the handler
        context = self._extract_function_context(handler_node, mcp_type)
        
        # Override name if explicitly provided
        if tool_name:
            context.name = tool_name
        
        return context

    def _extract_function_context(self, node: Node, mcp_type: str) -> KotlinFunctionContext:
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
        
        # Annotations
        annotations = self.parser.get_annotations(node)
        annotation_types = [self.parser.get_node_text(a) for a in annotations]
        
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
        
        # State manipulation
        global_writes = self._extract_global_writes(node)
        property_access = self._extract_property_access(node)
        
        # Dataflow summary
        dataflow_summary = self._create_dataflow_summary(node)
        
        return KotlinFunctionContext(
            name=name,
            annotation_types=annotation_types,
            annotation_params={},
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
            global_writes=global_writes,
            property_access=property_access,
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
            for child in self.parser.walk(call_node):
                if child.type == 'value_arguments':
                    for arg in child.children:
                        if arg.type == 'value_argument':
                            args.append(self.parser.get_node_text(arg))
            
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
            if assign_node.type in {'property_declaration', 'variable_declaration'}:
                # Handle val/var declarations
                var_name = ''
                var_value = ''
                
                for child in assign_node.children:
                    if child.type in {'simple_identifier', 'identifier'}:
                        var_name = self.parser.get_node_text(child)
                    elif child.type in {'call_expression', 'string_literal', 'integer_literal', 
                                       'boolean_literal', 'navigation_expression'}:
                        var_value = self.parser.get_node_text(child)
                
                if var_name:
                    assignments.append({
                        'variable': var_name,
                        'value': var_value or '<complex>',
                        'line': assign_node.start_point[0] + 1,
                        'type': 'declaration',
                    })
            
            elif assign_node.type == 'assignment':
                # Handle reassignments
                parts = []
                for child in assign_node.children:
                    if child.type not in {'='}:
                        parts.append(self.parser.get_node_text(child))
                
                if len(parts) >= 2:
                    assignments.append({
                        'variable': parts[0],
                        'value': parts[1],
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
        has_when = False
        
        for child in self.parser.walk(node):
            if child.type == 'if_expression':
                has_if = True
            elif child.type == 'for_statement':
                has_for = True
            elif child.type == 'while_statement':
                has_while = True
            elif child.type == 'try_expression':
                has_try = True
            elif child.type == 'when_expression':
                has_when = True
        
        return {
            'has_conditionals': has_if or has_when,
            'has_loops': has_for or has_while,
            'has_exception_handling': has_try,
            'has_when': has_when,
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
                if child.type in {'simple_identifier', 'identifier'} and self.parser.get_node_text(child) == param_name:
                    parent = child.parent
                    if parent:
                        if parent.type == 'call_expression':
                            call_name = self.parser.get_call_name(parent)
                            flow['reaches_calls'].append(call_name)
                            
                            call_lower = call_name.lower()
                            if any(p in call_lower for p in self.network_patterns + self.subprocess_patterns):
                                flow['reaches_external'] = True
                        
                        elif parent.type in {'assignment', 'property_declaration', 'variable_declaration'}:
                            flow['reaches_assignments'].append(self.parser.get_node_text(parent))
                        
                        elif parent.type == 'jump_expression':  # return
                            flow['reaches_returns'] = True
            
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
            if child.type == 'property_declaration':
                # Check if it's a val (immutable)
                is_val = False
                var_name = ''
                var_value = ''
                
                for subchild in child.children:
                    if subchild.type == 'val':
                        is_val = True
                    elif subchild.type in {'simple_identifier', 'identifier'}:
                        var_name = self.parser.get_node_text(subchild)
                    elif subchild.type in {'string_literal', 'integer_literal', 'boolean_literal'}:
                        var_value = self.parser.get_node_text(subchild)
                
                if is_val and var_name and var_value:
                    constants[var_name] = var_value
        
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
            var_name = ''
            deps = []
            
            for child in assign.children:
                if child.type in {'simple_identifier', 'identifier'} and not var_name:
                    var_name = self.parser.get_node_text(child)
                elif child.type not in {'val', 'var', '=', ':'}:
                    # Find identifiers in the value expression
                    for subchild in self.parser.walk(child):
                        if subchild.type in {'simple_identifier', 'identifier'}:
                            dep_name = self.parser.get_node_text(subchild)
                            if dep_name != var_name:
                                deps.append(dep_name)
            
            if var_name:
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
        """Check for eval/exec calls (reflection, script engines).

        Args:
            node: Function node

        Returns:
            True if eval/exec detected
        """
        dangerous_patterns = {'scriptengine', 'eval', 'invoke', 'reflection', 'kclass'}
        
        for call in self.parser.get_function_calls(node):
            call_name = self.parser.get_call_name(call).lower()
            if any(pattern in call_name for pattern in dangerous_patterns):
                return True
        
        return False

    def _has_dangerous_imports(self) -> bool:
        """Check for dangerous imports.

        Returns:
            True if dangerous imports detected
        """
        dangerous_modules = {'java.lang.runtime', 'processbuilder', 'scriptengine', 
                           'java.lang.reflect', 'kotlin.reflect'}
        
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
            if child.type in {'string_literal', 'line_string_literal'}:
                text = self.parser.get_node_text(child)
                # Remove quotes
                if text.startswith('"'):
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
            if child.type == 'jump_expression':
                # Check if it's a return
                for subchild in child.children:
                    if subchild.type == 'return':
                        # Get the return value
                        for value_child in child.children:
                            if value_child.type != 'return':
                                returns.append(self.parser.get_node_text(value_child))
        
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
            if child.type == 'catch_block':
                handler_info = {
                    'line': child.start_point[0] + 1,
                    'parameter': '',
                    'body_preview': '',
                }
                
                for subchild in child.children:
                    if subchild.type in {'simple_identifier', 'identifier'}:
                        handler_info['parameter'] = self.parser.get_node_text(subchild)
                    elif subchild.type == 'control_structure_body':
                        body_text = self.parser.get_node_text(subchild)
                        handler_info['body_preview'] = body_text[:100]
                
                handlers.append(handler_info)
        
        return handlers

    def _extract_global_writes(self, node: Node) -> List[Dict[str, Any]]:
        """Extract global/companion object writes.

        Args:
            node: Function node

        Returns:
            List of global write info
        """
        writes = []
        
        for child in self.parser.walk(node):
            if child.type == 'assignment':
                # Check if assigning to a navigation expression (could be global)
                for subchild in child.children:
                    if subchild.type == 'navigation_expression':
                        text = self.parser.get_node_text(subchild)
                        writes.append({
                            'target': text,
                            'line': child.start_point[0] + 1,
                        })
        
        return writes

    def _extract_property_access(self, node: Node) -> List[Dict[str, Any]]:
        """Extract property accesses.

        Args:
            node: Function node

        Returns:
            List of property access info
        """
        accesses = []
        
        for child in self.parser.walk(node):
            if child.type == 'navigation_expression':
                parts = []
                for subchild in child.children:
                    if subchild.type in {'simple_identifier', 'identifier'}:
                        parts.append(self.parser.get_node_text(subchild))
                
                if len(parts) >= 2:
                    accesses.append({
                        'object': parts[0],
                        'property': parts[-1],
                        'line': child.start_point[0] + 1,
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
            if 'statement' in child.type:
                statements += 1
            elif 'expression' in child.type:
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
            if child.type in {'if_expression', 'for_statement', 'while_statement',
                             'catch_block', 'when_entry'}:
                complexity += 1
            elif child.type == 'conjunction_expression':  # &&
                complexity += 1
            elif child.type == 'disjunction_expression':  # ||
                complexity += 1
        
        return complexity
