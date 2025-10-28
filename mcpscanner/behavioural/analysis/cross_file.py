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

"""Cross-file analysis for MCP servers with reversed approach.

REVERSED APPROACH: Track how MCP entry point parameters flow through
function calls across multiple files in the codebase.
"""

import ast
from pathlib import Path
from typing import Any, Dict, List, Set

from ..analyzers.base import BaseAnalyzer
from ..analyzers.python_analyzer import PythonAnalyzer


class CallGraph:
    """Call graph for cross-file analysis."""

    def __init__(self) -> None:
        """Initialize call graph."""
        self.functions: Dict[str, Any] = {}  # full_name -> function node
        self.calls: List[tuple[str, str]] = []  # (caller, callee) pairs
        self.mcp_entry_points: Set[str] = set()  # MCP decorated functions
        self.param_flows: Dict[str, Set[str]] = {}  # func -> params that flow through it

    def add_function(self, name: str, node: Any, file_path: Path, is_mcp_entry: bool = False) -> None:
        """Add a function definition.

        Args:
            name: Function name
            node: Function definition node
            file_path: File containing the function
            is_mcp_entry: Whether this is an MCP entry point
        """
        full_name = f"{file_path}::{name}"
        self.functions[full_name] = node
        if is_mcp_entry:
            self.mcp_entry_points.add(full_name)

    def add_call(self, caller: str, callee: str) -> None:
        """Add a function call edge.

        Args:
            caller: Caller function name
            callee: Callee function name
        """
        self.calls.append((caller, callee))

    def get_callees(self, func_name: str) -> List[str]:
        """Get functions called by a function.

        Args:
            func_name: Function name

        Returns:
            List of callee function names
        """
        return [callee for caller, callee in self.calls if caller == func_name]

    def get_mcp_entry_points(self) -> Set[str]:
        """Get all MCP entry point functions.

        Returns:
            Set of MCP entry point function names
        """
        return self.mcp_entry_points.copy()


class CrossFileAnalyzer:
    """Performs cross-file analysis for MCP servers.
    
    REVERSED APPROACH: Tracks parameter flow from MCP entry points through
    the entire codebase across multiple files.
    """

    def __init__(self) -> None:
        """Initialize cross-file analyzer."""
        self.call_graph = CallGraph()
        self.analyzers: Dict[Path, BaseAnalyzer] = {}
        self.import_map: Dict[Path, List[Path]] = {}  # file -> imported files

    def add_file(self, file_path: Path, source_code: str) -> None:
        """Add a file to the analysis.

        Args:
            file_path: Path to the file
            source_code: Source code content
        """
        analyzer = PythonAnalyzer(file_path, source_code)
        try:
            analyzer.parse()
            self.analyzers[file_path] = analyzer
            
            # Extract function definitions and MCP entry points
            self._extract_python_functions(file_path, analyzer)
            
            # Extract imports
            self._extract_imports(file_path, analyzer)
        except Exception:
            pass  # Skip files that can't be parsed

    def _extract_python_functions(self, file_path: Path, analyzer: PythonAnalyzer) -> None:
        """Extract function definitions from Python file.

        Args:
            file_path: File path
            analyzer: Python analyzer
        """
        func_defs = analyzer.get_function_defs()
        for func_def in func_defs:
            # Check if it's an MCP entry point
            is_mcp = self._is_mcp_entry_point(func_def)
            self.call_graph.add_function(func_def.name, func_def, file_path, is_mcp)

    def _is_mcp_entry_point(self, func_def: ast.FunctionDef) -> bool:
        """Check if function is an MCP entry point.

        Args:
            func_def: Function definition node

        Returns:
            True if MCP entry point
        """
        for decorator in func_def.decorator_list:
            decorator_name = self._get_decorator_name(decorator)
            # Support custom variable names: @hello_mcp.tool(), @jira_mcp.tool(), etc.
            if '.' in decorator_name:
                parts = decorator_name.rsplit('.', 1)
                if len(parts) == 2 and parts[1] in ['tool', 'prompt', 'resource']:
                    return True
        return False

    def _get_decorator_name(self, decorator: ast.expr) -> str:
        """Get decorator name.

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

    def _extract_imports(self, file_path: Path, analyzer: PythonAnalyzer) -> None:
        """Extract import relationships.

        Args:
            file_path: File path
            analyzer: Analyzer
        """
        imports = analyzer.get_imports()
        imported_files = []
        
        for import_node in imports:
            if isinstance(import_node, ast.Import):
                for alias in import_node.names:
                    module_name = alias.name
                    imported_file = self._resolve_python_import(file_path, module_name)
                    if imported_file:
                        imported_files.append(imported_file)
            elif isinstance(import_node, ast.ImportFrom):
                if import_node.module:
                    module_name = import_node.module
                    imported_file = self._resolve_python_import(file_path, module_name)
                    if imported_file:
                        imported_files.append(imported_file)
        
        self.import_map[file_path] = imported_files

    def _resolve_python_import(self, from_file: Path, module_name: str) -> Path | None:
        """Resolve Python import to file path.

        Args:
            from_file: File doing the import
            module_name: Module name

        Returns:
            Resolved file path or None
        """
        module_parts = module_name.split(".")
        current_dir = from_file.parent
        
        # Try relative to current file
        for i in range(len(module_parts), 0, -1):
            potential_path = current_dir / "/".join(module_parts[:i])
            
            # Try as file
            py_file = potential_path.with_suffix(".py")
            if py_file.exists():
                return py_file
            
            # Try as package
            init_file = potential_path / "__init__.py"
            if init_file.exists():
                return init_file
        
        return None

    def build_call_graph(self) -> CallGraph:
        """Build the complete call graph.

        Returns:
            Call graph
        """
        # Extract function calls from each file
        for file_path, analyzer in self.analyzers.items():
            self._extract_python_calls(file_path, analyzer)

        return self.call_graph

    def _extract_python_calls(self, file_path: Path, analyzer: PythonAnalyzer) -> None:
        """Extract function calls from Python file.

        Args:
            file_path: File path
            analyzer: Python analyzer
        """
        func_defs = analyzer.get_function_defs()
        
        # For each function, find calls within it
        for func_def in func_defs:
            caller_name = f"{file_path}::{func_def.name}"
            
            # Walk the function body to find calls
            for node in ast.walk(func_def):
                if isinstance(node, ast.Call):
                    callee_name = analyzer.get_call_name(node)
                    
                    # Try to resolve to full name
                    full_callee = self._resolve_call_target(file_path, callee_name)
                    
                    if full_callee:
                        self.call_graph.add_call(caller_name, full_callee)
                    else:
                        # Add with partial name (might be external library)
                        self.call_graph.add_call(caller_name, callee_name)

    def _resolve_call_target(self, file_path: Path, call_name: str) -> str | None:
        """Resolve a function call to its full qualified name.

        Args:
            file_path: File where call occurs
            call_name: Function call name

        Returns:
            Full qualified name or None
        """
        # Check if it's defined in the same file
        for func_name in self.call_graph.functions.keys():
            if func_name.endswith(f"::{call_name}"):
                if func_name.startswith(str(file_path)):
                    return func_name
        
        # Check imported files
        if file_path in self.import_map:
            for imported_file in self.import_map[file_path]:
                potential_name = f"{imported_file}::{call_name}"
                if potential_name in self.call_graph.functions:
                    return potential_name
        
        return None

    def get_reachable_functions(self, start_func: str) -> List[str]:
        """Get all functions reachable from a starting function (REVERSED APPROACH).

        Args:
            start_func: Starting function (MCP entry point)

        Returns:
            List of reachable function names
        """
        reachable = set()
        to_visit = [start_func]
        visited = set()
        
        while to_visit:
            current = to_visit.pop()
            if current in visited:
                continue
            
            visited.add(current)
            reachable.add(current)
            
            # Add all callees
            callees = self.call_graph.get_callees(current)
            for callee in callees:
                if callee not in visited:
                    to_visit.append(callee)
        
        return list(reachable)

    def analyze_parameter_flow_across_files(self, entry_point: str, param_names: List[str]) -> Dict[str, Any]:
        """Analyze how MCP entry point parameters flow across files.

        Args:
            entry_point: MCP entry point function name
            param_names: Parameter names to track

        Returns:
            Dictionary with cross-file flow information
        """
        # Get all functions reachable from entry point
        reachable = self.get_reachable_functions(entry_point)
        
        # Track which functions receive parameter data
        param_influenced_funcs = set()
        cross_file_flows = []
        
        for func_name in reachable:
            if func_name == entry_point:
                continue
            
            # Check if this function is called with parameter data
            for caller, callee in self.call_graph.calls:
                if callee == func_name and caller in [entry_point] + list(param_influenced_funcs):
                    param_influenced_funcs.add(func_name)
                    
                    # Extract file information
                    caller_file = caller.split("::")[0] if "::" in caller else "unknown"
                    callee_file = callee.split("::")[0] if "::" in callee else "unknown"
                    
                    if caller_file != callee_file:
                        cross_file_flows.append({
                            "from_function": caller,
                            "to_function": callee,
                            "from_file": caller_file,
                            "to_file": callee_file,
                        })
        
        return {
            "reachable_functions": reachable,
            "param_influenced_functions": list(param_influenced_funcs),
            "cross_file_flows": cross_file_flows,
            "total_files_involved": len(set(f.split("::")[0] for f in reachable if "::" in f)),
        }

    def get_all_files(self) -> List[Path]:
        """Get all files in the analysis.

        Returns:
            List of file paths
        """
        return list(self.analyzers.keys())
