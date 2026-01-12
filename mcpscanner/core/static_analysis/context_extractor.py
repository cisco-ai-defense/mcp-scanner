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

"""Code Context Extractor for Static Analysis.

This module extracts comprehensive code context from Python source by traversing
and analyzing Abstract Syntax Trees (AST). It provides:
- Extracts complete function context for MCP entry points
- Performs forward dataflow analysis from parameters
- Tracks taint flows to dangerous operations
- Collects constants, imports, and behavioral patterns
- Supports cross-file interprocedural analysis

Classes:
    FunctionContext: Complete context for a function
    ContextExtractor: Main extractor for comprehensive code analysis
"""

import ast
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from .parser.python_parser import PythonParser
from .dataflow.constant_propagation import ConstantPropagationAnalysis
from .dataflow.forward_analysis import ForwardDataflowAnalysis


@dataclass
class FunctionContext:
    """Complete context for a function."""
    # Required fields (no defaults)
    name: str
    decorator_types: List[str]
    imports: List[str]
    function_calls: List[Dict[str, Any]]
    assignments: List[Dict[str, Any]]
    control_flow: Dict[str, Any]
    parameter_flows: List[Dict[str, Any]]  # All paths from parameters
    constants: Dict[str, Any]
    variable_dependencies: Dict[str, List[str]]
    has_file_operations: bool
    has_network_operations: bool
    has_subprocess_calls: bool
    has_eval_exec: bool
    has_dangerous_imports: bool
    
    # Optional fields (with defaults)
    decorator_params: Dict[str, Dict[str, Any]] = field(default_factory=dict)  # Decorator parameters (name, description, tags, meta)
    docstring: Optional[str] = None
    parameters: List[Dict[str, Any]] = field(default_factory=list)
    return_type: Optional[str] = None
    line_number: int = 0
    
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
    
    # Dataflow facts
    dataflow_summary: Dict[str, Any] = field(default_factory=dict)


class ContextExtractor:
    """Extracts comprehensive code context by analyzing Abstract Syntax Trees.
    
    This class traverses Python ASTs (created by ast.parse()) to extract
    rich context information including dataflow, taint tracking, and behavioral
    patterns for security analysis.
    """
    
    # Configurable security pattern lists (can be overridden)
    DEFAULT_FILE_PATTERNS = ["open", "read", "write", "Path", "file", "os.remove", "os.unlink", "shutil"]
    DEFAULT_NETWORK_PATTERNS = ["requests", "urllib", "http", "socket", "post", "get", "fetch", "axios"]
    DEFAULT_SUBPROCESS_PATTERNS = ["subprocess", "os.system", "os.popen", "shell", "exec", "eval"]

    def __init__(
        self, 
        source_code: str, 
        file_path: str = "unknown.py",
        file_patterns: List[str] = None,
        network_patterns: List[str] = None,
        subprocess_patterns: List[str] = None
    ):
        """Initialize context extractor.

        Args:
            source_code: Python source code
            file_path: Path to source file
            file_patterns: Custom file operation patterns (default: DEFAULT_FILE_PATTERNS)
            network_patterns: Custom network operation patterns (default: DEFAULT_NETWORK_PATTERNS)
            subprocess_patterns: Custom subprocess patterns (default: DEFAULT_SUBPROCESS_PATTERNS)
        """
        self.source_code = source_code
        self.file_path = Path(file_path)
        self.analyzer = PythonParser(self.file_path, source_code)
        self.const_prop = ConstantPropagationAnalysis(self.analyzer)
        
        # Use provided patterns or defaults (convert to lowercase for case-insensitive matching)
        self.file_patterns = [p.lower() for p in (file_patterns or self.DEFAULT_FILE_PATTERNS)]
        self.network_patterns = [p.lower() for p in (network_patterns or self.DEFAULT_NETWORK_PATTERNS)]
        self.subprocess_patterns = [p.lower() for p in (subprocess_patterns or self.DEFAULT_SUBPROCESS_PATTERNS)]
        
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
    
    def _extract_decorator_params(self, decorator: ast.expr) -> dict[str, any]:
        """Extract parameters from decorator call.
        
        Extracts explicit parameters like name, description, tags, meta from
        @mcp.tool(name="...", description="...", tags={...}, meta={...})
        
        Args:
            decorator: Decorator node
            
        Returns:
            Dictionary of decorator parameters
        """
        params = {}
        
        if not isinstance(decorator, ast.Call):
            return params
        
        # Extract keyword arguments
        for keyword in decorator.keywords:
            if keyword.arg is None:
                continue
                
            try:
                # Handle different value types
                if isinstance(keyword.value, ast.Constant):
                    params[keyword.arg] = keyword.value.value
                elif isinstance(keyword.value, (ast.Set, ast.List, ast.Tuple)):
                    # Extract set/list/tuple literals
                    elements = []
                    for elt in keyword.value.elts:
                        if isinstance(elt, ast.Constant):
                            elements.append(elt.value)
                    params[keyword.arg] = elements
                elif isinstance(keyword.value, ast.Dict):
                    # Extract dict literals
                    dict_val = {}
                    for k, v in zip(keyword.value.keys, keyword.value.values):
                        if isinstance(k, ast.Constant) and isinstance(v, ast.Constant):
                            dict_val[k.value] = v.value
                    params[keyword.arg] = dict_val
                else:
                    # For complex expressions, store the unparsed representation
                    try:
                        params[keyword.arg] = ast.unparse(keyword.value)
                    except Exception:
                        params[keyword.arg] = "<complex expression>"
            except Exception:
                # Skip parameters we can't extract
                continue
        
        return params

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
        
        # Decorators - extract both names and parameters
        decorator_types = [self._get_decorator_name(d) for d in node.decorator_list]
        decorator_params = {}
        for decorator in node.decorator_list:
            dec_name = self._get_decorator_name(decorator)
            dec_params = self._extract_decorator_params(decorator)
            if dec_params:
                decorator_params[dec_name] = dec_params
        
        # Override name and docstring if explicitly specified in decorator
        # This handles cases like @mcp.tool(name="custom_name", description="...")
        for dec_name, params in decorator_params.items():
            if 'name' in params:
                name = params['name']  # Use decorator name if specified
            if 'description' in params and not docstring:
                docstring = params['description']  # Use decorator description if no docstring
        
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
        has_dangerous_imports = len(imports) > 0  # LLM will analyze all imports
        
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
        
        return FunctionContext(
            name=name,
            decorator_types=decorator_types,
            decorator_params=decorator_params,
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
                try:
                    param_info["type"] = ast.unparse(arg.annotation)
                except (AttributeError, TypeError, ValueError):
                    param_info["type"] = "<unknown>"
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
            try:
                return ast.unparse(node.returns)
            except (AttributeError, TypeError, ValueError):
                return "<unknown>"
        return None

    def _extract_imports(self, node: ast.FunctionDef) -> List[str]:
        """Extract all imports used in function, including module-level imports.

        Args:
            node: Function definition node

        Returns:
            List of import statements (both module-level and function-level)
        """
        imports = []
        
        # First, extract module-level imports from the entire AST
        for child in ast.walk(self.ast):
            if isinstance(child, ast.Import):
                for alias in child.names:
                    import_stmt = f"import {alias.name}"
                    if alias.asname:
                        import_stmt += f" as {alias.asname}"
                    if import_stmt not in imports:
                        imports.append(import_stmt)
            elif isinstance(child, ast.ImportFrom):
                module = child.module or ""
                for alias in child.names:
                    import_stmt = f"from {module} import {alias.name}"
                    if alias.asname:
                        import_stmt += f" as {alias.asname}"
                    if import_stmt not in imports:
                        imports.append(import_stmt)
        
        # Then, extract function-level imports (if any)
        for child in ast.walk(node):
            if isinstance(child, ast.Import):
                for alias in child.names:
                    import_stmt = f"import {alias.name}"
                    if alias.asname:
                        import_stmt += f" as {alias.asname}"
                    if import_stmt not in imports:
                        imports.append(import_stmt)
            elif isinstance(child, ast.ImportFrom):
                module = child.module or ""
                for alias in child.names:
                    import_stmt = f"from {module} import {alias.name}"
                    if alias.asname:
                        import_stmt += f" as {alias.asname}"
                    if import_stmt not in imports:
                        imports.append(import_stmt)
        
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
                args_list = []
                for arg in child.args:
                    try:
                        args_list.append(ast.unparse(arg))
                    except (AttributeError, TypeError, ValueError):
                        args_list.append("<complex>")
                
                call_info = {
                    "name": self._get_call_name(child),
                    "args": args_list,
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
            # Handle regular assignments (x = y)
            if isinstance(child, ast.Assign):
                for target in child.targets:
                    if isinstance(target, ast.Name):
                        try:
                            value_str = ast.unparse(child.value)
                        except (AttributeError, TypeError, ValueError):
                            value_str = "<complex>"
                        
                        assign_info = {
                            "variable": target.id,
                            "value": value_str,
                            "line": child.lineno if hasattr(child, "lineno") else 0,
                            "type": "assign"
                        }
                        assignments.append(assign_info)
            
            # Handle annotated assignments (x: int = y)
            elif isinstance(child, ast.AnnAssign):
                if isinstance(child.target, ast.Name):
                    try:
                        value_str = ast.unparse(child.value) if child.value else "<no value>"
                    except (AttributeError, TypeError, ValueError):
                        value_str = "<complex>"
                    
                    assign_info = {
                        "variable": child.target.id,
                        "value": value_str,
                        "line": child.lineno if hasattr(child, "lineno") else 0,
                        "type": "annotated_assign"
                    }
                    assignments.append(assign_info)
            
            # Handle augmented assignments (x += y, x -= y, etc.)
            elif isinstance(child, ast.AugAssign):
                if isinstance(child.target, ast.Name):
                    try:
                        value_str = ast.unparse(child.value)
                        op_str = child.op.__class__.__name__
                    except (AttributeError, TypeError, ValueError):
                        value_str = "<complex>"
                        op_str = "<unknown>"
                    
                    assign_info = {
                        "variable": child.target.id,
                        "value": f"{op_str}= {value_str}",
                        "line": child.lineno if hasattr(child, "lineno") else 0,
                        "type": "augmented_assign"
                    }
                    assignments.append(assign_info)
            
            # Handle named expressions / walrus operator (x := y)
            elif isinstance(child, ast.NamedExpr):
                if isinstance(child.target, ast.Name):
                    try:
                        value_str = ast.unparse(child.value)
                    except (AttributeError, TypeError, ValueError):
                        value_str = "<complex>"
                    
                    assign_info = {
                        "variable": child.target.id,
                        "value": value_str,
                        "line": child.lineno if hasattr(child, "lineno") else 0,
                        "type": "named_expr"
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
        has_for = any(isinstance(n, (ast.For, ast.AsyncFor)) for n in ast.walk(node))
        has_while = any(isinstance(n, ast.While) for n in ast.walk(node))
        has_try = any(isinstance(n, ast.Try) for n in ast.walk(node))
        has_match = any(isinstance(n, ast.Match) for n in ast.walk(node))  # Python 3.10+ pattern matching
        
        return {
            "has_conditionals": has_if or has_match,
            "has_loops": has_for or has_while,
            "has_exception_handling": has_try,
            "has_pattern_matching": has_match,
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
            try:
                func_source = ast.unparse(node)
            except (AttributeError, TypeError, ValueError) as e:
                self.logger.error(f"Failed to unparse function AST: {e}")
                return []
            
            func_analyzer = PythonParser(self.file_path, func_source)
            func_analyzer.parse()
            
            # Create forward flow tracker with the function-specific analyzer
            tracker = ForwardDataflowAnalysis(func_analyzer, param_names)
            
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
            # Handle regular assignments (x = y)
            if isinstance(child, ast.Assign):
                for target in child.targets:
                    if isinstance(target, ast.Name):
                        deps = []
                        for name_node in ast.walk(child.value):
                            if isinstance(name_node, ast.Name):
                                deps.append(name_node.id)
                        dependencies[target.id] = deps
            
            # Handle annotated assignments (x: int = y)
            elif isinstance(child, ast.AnnAssign):
                if isinstance(child.target, ast.Name) and child.value:
                    deps = []
                    for name_node in ast.walk(child.value):
                        if isinstance(name_node, ast.Name):
                            deps.append(name_node.id)
                    dependencies[child.target.id] = deps
            
            # Handle augmented assignments (x += y)
            elif isinstance(child, ast.AugAssign):
                if isinstance(child.target, ast.Name):
                    deps = [child.target.id]  # Depends on itself
                    for name_node in ast.walk(child.value):
                        if isinstance(name_node, ast.Name):
                            deps.append(name_node.id)
                    dependencies[child.target.id] = deps
            
            # Handle named expressions (x := y)
            elif isinstance(child, ast.NamedExpr):
                if isinstance(child.target, ast.Name):
                    deps = []
                    for name_node in ast.walk(child.value):
                        if isinstance(name_node, ast.Name):
                            deps.append(name_node.id)
                    dependencies[child.target.id] = deps
        
        return dependencies

    def _has_file_operations(self, node: ast.FunctionDef) -> bool:
        """Check for file operations.

        Args:
            node: Function definition node

        Returns:
            True if file operations detected
        """
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                call_name = self._get_call_name(child).lower()  # Case-insensitive
                if any(pattern in call_name for pattern in self.file_patterns):
                    return True
        return False

    def _has_network_operations(self, node: ast.FunctionDef) -> bool:
        """Check for network operations.

        Args:
            node: Function definition node

        Returns:
            True if network operations detected
        """
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                call_name = self._get_call_name(child).lower()  # Case-insensitive
                if any(pattern in call_name for pattern in self.network_patterns):
                    return True
        return False

    def _has_subprocess_calls(self, node: ast.FunctionDef) -> bool:
        """Check for subprocess calls.

        Args:
            node: Function definition node

        Returns:
            True if subprocess calls detected
        """
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                call_name = self._get_call_name(child).lower()  # Case-insensitive
                if any(pattern in call_name for pattern in self.subprocess_patterns):
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
