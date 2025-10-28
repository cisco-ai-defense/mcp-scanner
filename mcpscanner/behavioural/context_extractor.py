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
from .analysis.dataflow import ControlFlowGraph
from .analysis.forward_tracker import ForwardFlowTracker, FlowPath
from .analysis.naming import NameResolver
from .analysis.reaching_defs import ReachingDefinitionsAnalyzer
from .analysis.cross_file import CrossFileAnalyzer


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
    
    # Dataflow facts
    dataflow_summary: Dict[str, Any] = field(default_factory=dict)


class CodeContextExtractor:
    """Extracts comprehensive code context for LLM analysis."""

    def __init__(self, source_code: str, file_path: str = "unknown.py"):
        """Initialize context extractor.

        Args:
            source_code: Python source code
            file_path: Path to source file
        """
        self.source_code = source_code
        self.file_path = Path(file_path)
        self.analyzer = PythonAnalyzer(self.file_path, source_code)
        self.const_prop = ConstantPropagator(self.analyzer)
        
        # Parse and analyze
        try:
            self.ast = self.analyzer.parse()
            self.const_prop.analyze()
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
            tracker = ForwardFlowTracker(func_analyzer, param_names)
            
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
        """Extract constant values.

        Args:
            node: Function definition node

        Returns:
            Dictionary of constants
        """
        constants = {}
        for var_name, value in self.const_prop.constants.items():
            constants[var_name] = value
        return constants

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
