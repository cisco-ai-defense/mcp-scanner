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

"""Code context extractor for LLM-based analysis.

This module extracts comprehensive code context including:
- AST structure
- Dataflow information
- Taint analysis results
- Constant propagation
- Function call graphs
- Variable dependencies
"""

import ast
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from .analyzers.python_analyzer import PythonAnalyzer
from .analysis.constant_prop import ConstantPropagator
from .analysis.forward_tracker import ForwardFlowTracker
from .analysis.liveness import LivenessAnalyzer
from .analysis.available_exprs import AvailableExpressionsAnalyzer
from .analysis.naming import NameResolver
from .analysis.reaching_defs import ReachingDefinitionsAnalyzer


@dataclass
class FunctionContext:
    """Complete context for a function."""
    name: str
    decorator_types: List[str]
    docstring: Optional[str]
    parameters: List[Dict[str, Any]]
    return_type: Optional[str]
    line_number: int
    
    # Code structure
    imports: List[str]
    function_calls: List[Dict[str, Any]]
    assignments: List[Dict[str, Any]]
    control_flow: Dict[str, Any]
    
    # Analysis results (REVERSED APPROACH)
    parameter_flows: List[Dict[str, Any]]  # All paths from parameters
    constants: Dict[str, Any]
    variable_dependencies: Dict[str, List[str]]
    
    # Behavioral patterns
    has_file_operations: bool
    has_network_operations: bool
    has_subprocess_calls: bool
    has_eval_exec: bool
    has_dangerous_imports: bool
    
    # Cross-file analysis
    cross_file_calls: List[Dict[str, Any]] = field(default_factory=list)  # Calls to functions in other files
    reachable_functions: List[str] = field(default_factory=list)  # All functions reachable from this entry point
    
    # High-value security indicators
    string_literals: List[str] = field(default_factory=list)  # All string literals in function
    return_expressions: List[str] = field(default_factory=list)  # What the function returns
    exception_handlers: List[Dict[str, Any]] = field(default_factory=list)  # Exception handling details
    env_var_access: List[str] = field(default_factory=list)  # Environment variable accesses
    
    # State manipulation
    global_writes: List[Dict[str, Any]] = field(default_factory=list)  # global var = value
    attribute_access: List[Dict[str, Any]] = field(default_factory=list)  # self.attr or obj.attr
    
    # Advanced dataflow analysis
    dead_variables: List[str] = field(default_factory=list)  # Variables that are never used
    live_sensitive_vars: List[Dict[str, Any]] = field(default_factory=list)  # Sensitive data in memory
    unused_expressions: List[str] = field(default_factory=list)  # Computed but never used
    scope_issues: List[Dict[str, Any]] = field(default_factory=list)  # Scope/naming issues
    use_def_chains: Dict[str, List[str]] = field(default_factory=dict)  # Variable use-def chains
    
    # Dataflow facts
    dataflow_summary: Dict[str, Any] = field(default_factory=dict)


class CodeContextExtractor:
    """Extracts comprehensive code context for LLM analysis."""

    def __init__(self, source_code: str, file_path: str = "unknown.py", call_graph=None):
        """Initialize context extractor.

        Args:
            source_code: Python source code to analyze
            file_path: Path to the source file
            call_graph: Optional CallGraph for inter-procedural analysis
        """
        self.source_code = source_code
        self.file_path = file_path
        self.analyzer = PythonAnalyzer(file_path, source_code)
        self.analyzer.parse()
        self.const_prop = ConstantPropagator(self.analyzer)
        self.call_graph = call_graph
        self.logger = logging.getLogger(__name__)
        self._const_prop_analyzed = False  # Lazy evaluation flag
        try:
            self.ast = self.analyzer.parse()
            # Don't run const_prop.analyze() upfront - do it on-demand
        except SyntaxError as e:
            raise ValueError(f"Failed to parse source code: {e}")

    def extract_mcp_function_contexts(self) -> List[FunctionContext]:
        """Extract contexts for all MCP-decorated functions.

        Returns:
            List of function contexts
        """
        contexts = []
        
        for node in ast.walk(self.ast):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            
            # Check for MCP decorators
            mcp_decorator = self._get_mcp_decorator(node)
            if not mcp_decorator:
                continue
            
            context = self._extract_function_context(node, mcp_decorator)
            contexts.append(context)
        
        return contexts

    def _get_mcp_decorator(self, node: ast.FunctionDef) -> Optional[str]:
        """Get MCP decorator type if present.

        Args:
            node: Function definition node

        Returns:
            Decorator type or None
        """
        for decorator in node.decorator_list:
            decorator_name = self._get_decorator_name(decorator)
            
            # Check if decorator matches pattern: <any_variable>.tool/prompt/resource
            # Examples: mcp.tool, hello_mcp.tool, my_server.prompt, etc.
            if '.' in decorator_name:
                # Split on the last dot to get the method name
                parts = decorator_name.rsplit('.', 1)
                if len(parts) == 2:
                    method_name = parts[1].lower()
                    # Check if it's one of the MCP decorator methods
                    if method_name in ['tool', 'prompt', 'resource']:
                        return decorator_name
            
            # Fallback: check if decorator name contains tool, prompt, or resource
            # This handles edge cases like direct function decorators
            decorator_lower = decorator_name.lower()
            if decorator_lower in ['tool', 'prompt', 'resource']:
                return decorator_name
        
        return None

    def _get_decorator_name(self, decorator: ast.expr) -> str:
        """Extract decorator name.

        Args:
            decorator: Decorator node

        Returns:
            Decorator name
        """
        if isinstance(decorator, ast.Call):
            decorator = decorator.func
        
        if isinstance(decorator, ast.Attribute):
            if isinstance(decorator.value, ast.Name):
                return f"{decorator.value.id}.{decorator.attr}"
        elif isinstance(decorator, ast.Name):
            return decorator.id
        
        return ""

    def _extract_function_context(
        self, node: ast.FunctionDef, decorator_type: str
    ) -> FunctionContext:
        """Extract complete context for a function.

        Args:
            node: Function definition node
            decorator_type: MCP decorator type

        Returns:
            Function context
        """
        # Basic info
        name = node.name
        docstring = ast.get_docstring(node)
        parameters = self._extract_parameters(node)
        return_type = self._extract_return_type(node)
        line_number = node.lineno
        
        # Decorators
        decorator_types = [self._get_decorator_name(d) for d in node.decorator_list]
        
        # Code structure
        imports = self._extract_imports(node)
        function_calls = self._extract_function_calls(node)
        assignments = self._extract_assignments(node)
        control_flow = self._analyze_control_flow(node)
        
        # REVERSED APPROACH: Forward flow analysis from parameters
        parameter_flows = self._analyze_forward_flows(node, parameters)
        
        # Constants
        constants = self._extract_constants(node)
        
        # Variable dependencies
        var_deps = self._analyze_variable_dependencies(node)
        
        # Behavioral patterns
        has_file_ops = self._has_file_operations(node)
        has_network_ops = self._has_network_operations(node)
        has_subprocess = self._has_subprocess_calls(node)
        has_eval_exec = self._has_eval_exec(node)
        has_dangerous_imports = self._has_dangerous_imports(imports)
        
        # Dataflow summary
        dataflow_summary = self._create_dataflow_summary(node)
        
        # High-value security indicators
        string_literals = self._extract_string_literals(node)
        return_expressions = self._extract_return_expressions(node)
        exception_handlers = self._extract_exception_handlers(node)
        env_var_access = self._extract_env_var_access(node)
        
        # State manipulation
        global_writes = self._extract_global_writes(node)
        attribute_access = self._extract_attribute_access(node)
        
        # Advanced dataflow analysis
        param_names = [p['name'] for p in parameters]
        dead_vars, live_sensitive, unused_exprs = self._extract_liveness_and_availability(node, param_names)
        scope_issues, use_def_chains = self._extract_name_resolution_and_reaching_defs(node, param_names)
        
        return FunctionContext(
            name=name,
            decorator_types=decorator_types,
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
            dead_variables=dead_vars,
            live_sensitive_vars=live_sensitive,
            unused_expressions=unused_exprs,
            scope_issues=scope_issues,
            use_def_chains=use_def_chains,
        )

    def _extract_parameters(self, node: ast.FunctionDef) -> List[Dict[str, Any]]:
        """Extract function parameters with type hints.

        Args:
            node: Function definition node

        Returns:
            List of parameter info
        """
        params = []
        for arg in node.args.args:
            param_info = {"name": arg.arg}
            if arg.annotation:
                param_info["type"] = ast.unparse(arg.annotation)
            params.append(param_info)
        return params

    def _extract_return_type(self, node: ast.FunctionDef) -> Optional[str]:
        """Extract return type annotation.

        Args:
            node: Function definition node

        Returns:
            Return type or None
        """
        if node.returns:
            return ast.unparse(node.returns)
        return None

    def _extract_imports(self, node: ast.FunctionDef) -> List[str]:
        """Extract all imports used in function.

        Args:
            node: Function definition node

        Returns:
            List of import statements
        """
        imports = []
        for child in ast.walk(node):
            if isinstance(child, ast.Import):
                for alias in child.names:
                    imports.append(f"import {alias.name}")
            elif isinstance(child, ast.ImportFrom):
                module = child.module or ""
                for alias in child.names:
                    imports.append(f"from {module} import {alias.name}")
        return imports

    def _extract_function_calls(self, node: ast.FunctionDef) -> List[Dict[str, Any]]:
        """Extract all function calls with arguments.

        Args:
            node: Function definition node

        Returns:
            List of function call info
        """
        calls = []
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                call_info = {
                    "name": self._get_call_name(child),
                    "args": [ast.unparse(arg) for arg in child.args],
                    "line": child.lineno if hasattr(child, "lineno") else 0,
                }
                calls.append(call_info)
        return calls

    def _get_call_name(self, node: ast.Call) -> str:
        """Get function call name.

        Args:
            node: Call node

        Returns:
            Function name
        """
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts))
        return ast.unparse(node.func)

    def _extract_assignments(self, node: ast.FunctionDef) -> List[Dict[str, Any]]:
        """Extract all assignments.

        Args:
            node: Function definition node

        Returns:
            List of assignment info
        """
        assignments = []
        for child in ast.walk(node):
            if isinstance(child, ast.Assign):
                for target in child.targets:
                    if isinstance(target, ast.Name):
                        assign_info = {
                            "variable": target.id,
                            "value": ast.unparse(child.value),
                            "line": child.lineno if hasattr(child, "lineno") else 0,
                        }
                        assignments.append(assign_info)
        return assignments

    def _analyze_control_flow(self, node: ast.FunctionDef) -> Dict[str, Any]:
        """Analyze control flow structure.

        Args:
            node: Function definition node

        Returns:
            Control flow summary
        """
        has_if = any(isinstance(n, ast.If) for n in ast.walk(node))
        has_for = any(isinstance(n, ast.For) for n in ast.walk(node))
        has_while = any(isinstance(n, ast.While) for n in ast.walk(node))
        has_try = any(isinstance(n, ast.Try) for n in ast.walk(node))
        
        return {
            "has_conditionals": has_if,
            "has_loops": has_for or has_while,
            "has_exception_handling": has_try,
        }

    def _analyze_forward_flows(
        self, node: ast.FunctionDef, parameters: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Analyze forward flows from parameters (REVERSED APPROACH).

        Args:
            node: Function definition node
            parameters: Function parameters

        Returns:
            List of flow paths from each parameter
        """
        try:
            # Extract parameter names
            param_names = [p["name"] for p in parameters]
            
            if not param_names:
                return []
            
            # PERFORMANCE FIX: Create a new analyzer with ONLY this function's AST
            # instead of the entire file. This makes the CFG much smaller and faster.
            func_source = ast.unparse(node)
            func_analyzer = PythonAnalyzer(self.file_path, func_source)
            func_analyzer.parse()
            
            # Create forward flow tracker with the function-specific analyzer
            # Pass call_graph for inter-procedural analysis (follows calls across files)
            tracker = ForwardFlowTracker(func_analyzer, param_names, 
                                        call_graph=self.call_graph, max_depth=3)
            
            # Analyze flows from parameters
            flows = tracker.analyze_forward_flows()
            
            # Convert to serializable format
            flow_data = []
            for flow in flows:
                flow_data.append({
                    "parameter": flow.parameter_name,
                    "operations": flow.operations,
                    "reaches_calls": flow.reaches_calls,
                    "reaches_assignments": flow.reaches_assignments,
                    "reaches_returns": flow.reaches_returns,
                    "reaches_external": flow.reaches_external,
                })
            
            return flow_data
        except Exception as e:
            self.logger.error(f"Forward flow analysis failed: {e}")
            return []

    def _extract_constants(self, node: ast.FunctionDef) -> Dict[str, Any]:
        """Extract constant values on-demand (only for external ops/control flow).

        Args:
            node: Function definition node

        Returns:
            Dictionary of constants (sparse - only relevant ones)
        """
        # Run const prop analysis only if not done yet (lazy)
        if not self._const_prop_analyzed:
            try:
                self.const_prop.analyze()
                self._const_prop_analyzed = True
            except:
                return {}
        
        # Only extract constants that are used in external operations or control flow
        constants = {}
        relevant_vars = self._find_relevant_constant_vars(node)
        
        for var_name in relevant_vars:
            if var_name in self.const_prop.constants:
                constants[var_name] = self.const_prop.constants[var_name]
        
        return constants
    
    def _find_relevant_constant_vars(self, node: ast.FunctionDef) -> set:
        """Find variables that need constant propagation (sparse).
        
        Only variables used in:
        - External operations (HTTP, subprocess, file I/O)
        - Control flow conditions
        - Return statements
        """
        relevant = set()
        
        for child in ast.walk(node):
            # Variables in function calls (potential external ops)
            if isinstance(child, ast.Call):
                for arg in child.args:
                    if isinstance(arg, ast.Name):
                        relevant.add(arg.id)
            
            # Variables in conditionals
            elif isinstance(child, (ast.If, ast.While)):
                for name_node in ast.walk(child.test):
                    if isinstance(name_node, ast.Name):
                        relevant.add(name_node.id)
            
            # Variables in returns
            elif isinstance(child, ast.Return) and child.value:
                for name_node in ast.walk(child.value):
                    if isinstance(name_node, ast.Name):
                        relevant.add(name_node.id)
        
        return relevant

    def _analyze_variable_dependencies(self, node: ast.FunctionDef) -> Dict[str, List[str]]:
        """Analyze variable dependencies.

        Args:
            node: Function definition node

        Returns:
            Dictionary mapping variables to their dependencies
        """
        dependencies = {}
        
        for child in ast.walk(node):
            if isinstance(child, ast.Assign):
                for target in child.targets:
                    if isinstance(target, ast.Name):
                        deps = []
                        for name_node in ast.walk(child.value):
                            if isinstance(name_node, ast.Name):
                                deps.append(name_node.id)
                        dependencies[target.id] = deps
        
        return dependencies

    def _has_file_operations(self, node: ast.FunctionDef) -> bool:
        """Check for file operations.

        Args:
            node: Function definition node

        Returns:
            True if file operations detected
        """
        file_patterns = ["open", "read", "write", "Path", "file"]
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                call_name = self._get_call_name(child)
                if any(pattern in call_name for pattern in file_patterns):
                    return True
        return False

    def _has_network_operations(self, node: ast.FunctionDef) -> bool:
        """Check for network operations.

        Args:
            node: Function definition node

        Returns:
            True if network operations detected
        """
        network_patterns = ["requests", "urllib", "http", "socket", "post", "get"]
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                call_name = self._get_call_name(child)
                if any(pattern in call_name for pattern in network_patterns):
                    return True
        return False

    def _has_subprocess_calls(self, node: ast.FunctionDef) -> bool:
        """Check for subprocess calls.

        Args:
            node: Function definition node

        Returns:
            True if subprocess calls detected
        """
        subprocess_patterns = ["subprocess", "os.system", "os.popen", "shell"]
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                call_name = self._get_call_name(child)
                if any(pattern in call_name for pattern in subprocess_patterns):
                    return True
        return False

    def _has_eval_exec(self, node: ast.FunctionDef) -> bool:
        """Check for eval/exec calls.

        Args:
            node: Function definition node

        Returns:
            True if eval/exec detected
        """
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                call_name = self._get_call_name(child)
                if call_name in ["eval", "exec", "compile", "__import__"]:
                    return True
        return False

    def _has_dangerous_imports(self, imports: List[str]) -> bool:
        """Check for dangerous imports.

        Args:
            imports: List of import statements

        Returns:
            True if dangerous imports detected
        """
        dangerous = ["subprocess", "os", "eval", "exec", "pickle", "marshal"]
        return any(danger in imp for danger in dangerous for imp in imports)

    def _create_dataflow_summary(self, node: ast.FunctionDef) -> Dict[str, Any]:
        """Create dataflow summary.

        Args:
            node: Function definition node

        Returns:
            Dataflow summary
        """
        return {
            "total_statements": len([n for n in ast.walk(node) if isinstance(n, ast.stmt)]),
            "total_expressions": len([n for n in ast.walk(node) if isinstance(n, ast.expr)]),
            "complexity": self._calculate_complexity(node),
        }

    def _calculate_complexity(self, node: ast.FunctionDef) -> int:
        """Calculate cyclomatic complexity.

        Args:
            node: Function definition node

        Returns:
            Complexity score
        """
        complexity = 1
        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.For, ast.While, ast.ExceptHandler)):
                complexity += 1
            elif isinstance(child, ast.BoolOp):
                complexity += len(child.values) - 1
        return complexity
    
    def _extract_string_literals(self, node: ast.FunctionDef) -> List[str]:
        """Extract all string literals from function.
        
        Args:
            node: Function definition node
            
        Returns:
            List of string literals
        """
        literals = []
        for child in ast.walk(node):
            if isinstance(child, ast.Constant) and isinstance(child.value, str):
                # Limit length to avoid huge strings
                literal = child.value[:200]
                if literal and literal not in literals:
                    literals.append(literal)
        return literals[:20]  # Limit to 20 strings
    
    def _extract_return_expressions(self, node: ast.FunctionDef) -> List[str]:
        """Extract return expressions from function.
        
        Args:
            node: Function definition node
            
        Returns:
            List of return expression strings
        """
        returns = []
        for child in ast.walk(node):
            if isinstance(child, ast.Return) and child.value:
                try:
                    return_expr = ast.unparse(child.value)[:100]
                    returns.append(return_expr)
                except Exception:
                    returns.append("<unparseable>")
        return returns
    
    def _extract_exception_handlers(self, node: ast.FunctionDef) -> List[Dict[str, Any]]:
        """Extract exception handling details.
        
        Args:
            node: Function definition node
            
        Returns:
            List of exception handler info
        """
        handlers = []
        for child in ast.walk(node):
            if isinstance(child, ast.ExceptHandler):
                handler_info = {
                    "line": child.lineno,
                    "exception_type": ast.unparse(child.type) if child.type else "Exception",
                    "has_body": len(child.body) > 0,
                    "is_silent": len(child.body) == 1 and isinstance(child.body[0], ast.Pass)
                }
                handlers.append(handler_info)
        return handlers
    
    def _extract_env_var_access(self, node: ast.FunctionDef) -> List[str]:
        """Extract environment variable accesses.
        
        Args:
            node: Function definition node
            
        Returns:
            List of env var access patterns
        """
        env_accesses = []
        for child in ast.walk(node):
            # os.environ.get('KEY'), os.getenv('KEY'), etc.
            if isinstance(child, ast.Call):
                call_name = ""
                if isinstance(child.func, ast.Attribute):
                    if isinstance(child.func.value, ast.Attribute):
                        # os.environ.get
                        if isinstance(child.func.value.value, ast.Name):
                            call_name = f"{child.func.value.value.id}.{child.func.value.attr}.{child.func.attr}"
                    elif isinstance(child.func.value, ast.Name):
                        # os.getenv
                        call_name = f"{child.func.value.id}.{child.func.attr}"
                
                if "environ" in call_name or "getenv" in call_name:
                    # Try to get the key name
                    if child.args and isinstance(child.args[0], ast.Constant):
                        key = child.args[0].value
                        env_accesses.append(f"{call_name}('{key}')")
                    else:
                        env_accesses.append(call_name)
        
        return env_accesses
    
    def _extract_global_writes(self, node: ast.FunctionDef) -> List[Dict[str, Any]]:
        """Extract global variable writes.
        
        Args:
            node: Function definition node
            
        Returns:
            List of global write operations
        """
        global_writes = []
        global_vars = set()
        
        # First, find all global declarations
        for child in ast.walk(node):
            if isinstance(child, ast.Global):
                global_vars.update(child.names)
        
        # Then find assignments to those globals
        for child in ast.walk(node):
            if isinstance(child, ast.Assign):
                for target in child.targets:
                    if isinstance(target, ast.Name) and target.id in global_vars:
                        try:
                            value_str = ast.unparse(child.value)[:100]
                        except Exception:
                            value_str = "<complex>"
                        
                        global_writes.append({
                            "variable": target.id,
                            "value": value_str,
                            "line": child.lineno
                        })
        
        return global_writes
    
    def _extract_attribute_access(self, node: ast.FunctionDef) -> List[Dict[str, Any]]:
        """Extract attribute access patterns (self.attr, obj.attr).
        
        Args:
            node: Function definition node
            
        Returns:
            List of attribute access operations
        """
        attribute_ops = []
        
        for child in ast.walk(node):
            # Attribute writes: self.attr = value or obj.attr = value
            if isinstance(child, ast.Assign):
                for target in child.targets:
                    if isinstance(target, ast.Attribute):
                        obj_name = ""
                        if isinstance(target.value, ast.Name):
                            obj_name = target.value.id
                        
                        try:
                            value_str = ast.unparse(child.value)[:100]
                        except Exception:
                            value_str = "<complex>"
                        
                        attribute_ops.append({
                            "type": "write",
                            "object": obj_name,
                            "attribute": target.attr,
                            "value": value_str,
                            "line": child.lineno
                        })
            
            # Attribute reads: x = self.attr or obj.attr
            elif isinstance(child, ast.Attribute):
                obj_name = ""
                if isinstance(child.value, ast.Name):
                    obj_name = child.value.id
                
                # Only track interesting objects (self, class instances, etc.)
                if obj_name and obj_name not in ['str', 'int', 'list', 'dict']:
                    attribute_ops.append({
                        "type": "read",
                        "object": obj_name,
                        "attribute": child.attr,
                        "line": child.lineno
                    })
        
        # Deduplicate and limit
        seen = set()
        unique_ops = []
        for op in attribute_ops:
            key = (op['type'], op['object'], op['attribute'])
            if key not in seen:
                seen.add(key)
                unique_ops.append(op)
                if len(unique_ops) >= 20:
                    break
        
        return unique_ops
    
    def _extract_liveness_and_availability(
        self, 
        node: ast.FunctionDef, 
        param_names: List[str]
    ) -> tuple[List[str], List[Dict[str, Any]], List[str]]:
        """Extract liveness and available expressions analysis.
        
        Args:
            node: Function definition node
            param_names: Parameter names
            
        Returns:
            Tuple of (dead_variables, live_sensitive_vars, unused_expressions)
        """
        dead_vars = []
        live_sensitive = []
        unused_exprs = []
        
        try:
            # Run liveness analysis
            liveness_analyzer = LivenessAnalyzer(self.analyzer, param_names)
            live_vars_map = liveness_analyzer.analyze_liveness()
            
            # Find dead variables (assigned but never used)
            all_assigned = set()
            all_used = set()
            
            for child in ast.walk(node):
                if isinstance(child, ast.Assign):
                    for target in child.targets:
                        if isinstance(target, ast.Name):
                            all_assigned.add(target.id)
                elif isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
                    all_used.add(child.id)
            
            dead_vars = list(all_assigned - all_used)
            
            # Run available expressions analysis
            avail_analyzer = AvailableExpressionsAnalyzer(self.analyzer, param_names)
            available_exprs = avail_analyzer.analyze_available_exprs()
            
            # Find expressions that are computed but never used
            # Look for function calls in expression statements (not assigned to anything)
            for child in ast.walk(node):
                if isinstance(child, ast.Expr) and isinstance(child.value, ast.Call):
                    try:
                        call_str = ast.unparse(child.value)
                        unused_exprs.append(call_str)
                    except Exception:
                        pass
        
        except Exception as e:
            # If analysis fails, return empty results
            self.logger.debug(f"Liveness/availability analysis failed: {e}")
        
        return dead_vars, live_sensitive, unused_exprs
    
    def _extract_name_resolution_and_reaching_defs(
        self,
        node: ast.FunctionDef,
        param_names: List[str]
    ) -> tuple[List[Dict[str, Any]], Dict[str, List[str]]]:
        """Extract name resolution and reaching definitions analysis.
        
        Args:
            node: Function definition node
            param_names: Parameter names
            
        Returns:
            Tuple of (scope_issues, use_def_chains)
        """
        scope_issues = []
        use_def_chains = {}
        
        try:
            # Run name resolution
            name_resolver = NameResolver(self.analyzer, param_names)
            name_resolver.resolve()
            
            # Check for scope issues
            # 1. Variables used before definition (excluding function calls)
            defined_vars = set()
            function_calls = set()
            
            # First pass: collect all function calls and decorators
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    if isinstance(child.func, ast.Name):
                        function_calls.add(child.func.id)
                    elif isinstance(child.func, ast.Attribute):
                        # Handle obj.method() calls
                        if isinstance(child.func.value, ast.Name):
                            function_calls.add(child.func.value.id)
            
            # Second pass: check for variables used before definition
            for child in ast.walk(node):
                if isinstance(child, ast.Assign):
                    for target in child.targets:
                        if isinstance(target, ast.Name):
                            defined_vars.add(target.id)
                elif isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
                    # Skip if it's a function call, parameter, or builtin
                    if (child.id not in defined_vars and 
                        child.id not in param_names and
                        child.id not in function_calls and
                        not self._is_builtin_or_import(child.id)):
                        scope_issues.append({
                            'type': 'used_before_definition',
                            'variable': child.id,
                            'line': getattr(child, 'lineno', 0)
                        })
            
            # Run reaching definitions
            reaching_defs = ReachingDefinitionsAnalyzer(self.analyzer, param_names)
            use_def_map = reaching_defs.analyze_reaching_defs()
            
            # Build simplified use-def chains for LLM
            for (node_id, var), defs in use_def_map.items():
                if var not in use_def_chains:
                    use_def_chains[var] = []
                for definition in defs:
                    if definition.is_parameter:
                        use_def_chains[var].append(f"parameter:{definition.var}")
                    else:
                        use_def_chains[var].append(f"line:{definition.node_id}")
            
        except Exception as e:
            self.logger.debug(f"Name resolution/reaching defs analysis failed: {e}")
        
        return scope_issues, use_def_chains
    
    def _is_builtin_or_import(self, name: str) -> bool:
        """Check if name is a builtin or imported.
        
        Args:
            name: Variable name
            
        Returns:
            True if builtin or imported
        """
        import builtins
        return name in dir(builtins) or name in ['self', 'cls']

    def to_json(self, contexts: List[FunctionContext]) -> str:
        """Convert contexts to JSON for LLM.

        Args:
            contexts: List of function contexts

        Returns:
            JSON string
        """
        data = []
        for ctx in contexts:
            data.append({
                "name": ctx.name,
                "decorator_types": ctx.decorator_types,
                "docstring": ctx.docstring,
                "parameters": ctx.parameters,
                "return_type": ctx.return_type,
                "line_number": ctx.line_number,
                "imports": ctx.imports,
                "function_calls": ctx.function_calls,
                "assignments": ctx.assignments,
                "control_flow": ctx.control_flow,
                "taint_sources": ctx.taint_sources,
                "taint_sinks": ctx.taint_sinks,
                "taint_flows": ctx.taint_flows,
                "constants": ctx.constants,
                "variable_dependencies": ctx.variable_dependencies,
                "has_file_operations": ctx.has_file_operations,
                "has_network_operations": ctx.has_network_operations,
                "has_subprocess_calls": ctx.has_subprocess_calls,
                "has_eval_exec": ctx.has_eval_exec,
                "has_dangerous_imports": ctx.has_dangerous_imports,
                "dataflow_summary": ctx.dataflow_summary,
            })
        return json.dumps(data, indent=2)
