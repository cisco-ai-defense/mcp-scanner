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
import logging
import threading
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

from ..parser.base import BaseParser
from ..parser.python_parser import PythonParser
from ..semantic.type_analyzer import TypeAnalyzer


class CallGraph:
    """Call graph for cross-file analysis.

    Maintains both the raw edge list (``calls``) for backwards compatibility
    and adjacency / reverse-adjacency / short-name indices that turn the
    common queries (``get_callees``, ``get_callers``, BFS reachability,
    name-based call resolution) from O(edges) / O(functions) per query into
    amortized O(1) lookups + O(out-degree) traversal. The indices are kept
    in sync inside ``add_function`` / ``add_call`` so callers don't need to
    explicitly "finalize" the graph; the duplicate-edge guard means it is
    safe (and cheap) to call ``add_call`` from multiple AST passes that may
    legitimately encounter the same call site twice.
    """

    def __init__(self) -> None:
        """Initialize call graph."""
        self.functions: Dict[str, Any] = {}  # full_name -> function node
        self.calls: List[Tuple[str, str]] = []  # (caller, callee) pairs
        self.mcp_entry_points: Set[str] = set()  # MCP decorated functions

        # Performance indices (see class docstring). ``_callees`` /
        # ``_callers`` mirror ``self.calls`` as forward / reverse adjacency
        # lists; ``_edges`` deduplicates so the lists stay tight even when
        # ``add_call`` is invoked from overlapping AST visitors.
        self._callees: Dict[str, List[str]] = defaultdict(list)
        self._callers: Dict[str, List[str]] = defaultdict(list)
        self._edges: Set[Tuple[str, str]] = set()

        # Short-name → full-name index used by ``_resolve_call_target`` to
        # avoid an O(N) scan of ``self.functions`` on every call site. We
        # index under both the trailing component (e.g. ``method`` for
        # ``Class.method``) and the full short name so resolution can prefer
        # a same-file match before falling back to the global candidate set.
        self._functions_by_short: Dict[str, List[str]] = defaultdict(list)

        # ``BehavioralCodeAnalyzer`` parses files in a thread pool to overlap
        # the heavy ``ast.parse`` + ``TypeAnalyzer.analyze`` cost with disk
        # I/O. The actual mutations of the indices below are short, so a
        # single lock around the registration helpers is enough to keep the
        # graph consistent without serializing the heavy parsing work.
        self._mutation_lock = threading.Lock()

    def add_function(
        self, name: str, node: Any, file_path: Path, is_mcp_entry: bool = False
    ) -> None:
        """Add a function definition.

        Args:
            name: Function name
            node: Function definition node
            file_path: File containing the function
            is_mcp_entry: Whether this is an MCP entry point
        """
        full_name = f"{file_path}::{name}"
        with self._mutation_lock:
            if full_name in self.functions:
                # Re-adding the same function (e.g. when a file is parsed
                # twice) would otherwise create duplicate short-name entries.
                # Skip the index updates; ``self.functions[full_name]``
                # already points at the correct node.
                if is_mcp_entry:
                    self.mcp_entry_points.add(full_name)
                return
            self.functions[full_name] = node
            if is_mcp_entry:
                self.mcp_entry_points.add(full_name)

            # Index under both the full short name (``name``) and the
            # trailing component (``Class.method`` → also ``method``) so
            # call resolution can match either form without scanning all
            # functions.
            self._functions_by_short[name].append(full_name)
            if "." in name:
                self._functions_by_short[name.rsplit(".", 1)[-1]].append(full_name)

    def add_call(self, caller: str, callee: str) -> None:
        """Add a function call edge.

        Args:
            caller: Caller function name
            callee: Callee function name
        """
        edge = (caller, callee)
        with self._mutation_lock:
            if edge in self._edges:
                return  # AST walks frequently re-emit the same edge; ignore dupes
            self._edges.add(edge)
            self.calls.append(edge)
            self._callees[caller].append(callee)
            self._callers[callee].append(caller)

    def get_callees(self, func_name: str) -> List[str]:
        """Get functions called by a function.

        Args:
            func_name: Function name

        Returns:
            List of callee function names
        """
        # ``defaultdict.get`` avoids inserting an empty list on misses, which
        # keeps the index tight when callers probe for unknown functions.
        callees = self._callees.get(func_name)
        return list(callees) if callees else []

    def get_callers(self, func_name: str) -> List[str]:
        """Get functions that call ``func_name``.

        The reverse index lets ``analyze_parameter_flow_across_files`` and
        similar consumers iterate predecessors without scanning every edge.
        """
        callers = self._callers.get(func_name)
        return list(callers) if callers else []

    def get_functions_by_short_name(self, short_name: str) -> List[str]:
        """Return all fully-qualified function names matching ``short_name``.

        The list contains every function that was registered with this short
        name (or whose trailing ``Class.method`` component matches it). This
        is the primary index used by ``CallGraphAnalyzer._resolve_call_target``
        to turn name resolution into an O(1) lookup.
        """
        candidates = self._functions_by_short.get(short_name)
        return list(candidates) if candidates else []

    def get_mcp_entry_points(self) -> Set[str]:
        """Get all MCP entry point functions.

        Returns:
            Set of MCP entry point function names
        """
        return self.mcp_entry_points.copy()


class CallGraphAnalyzer:
    """Performs cross-file analysis for MCP servers.

    REVERSED APPROACH: Tracks parameter flow from MCP entry points through
    the entire codebase across multiple files.
    """

    def __init__(self) -> None:
        """Initialize cross-file analyzer."""
        self.call_graph = CallGraph()
        self.analyzers: Dict[Path, BaseParser] = {}
        self.import_map: Dict[Path, List[Path]] = {}  # file -> imported files
        self.type_analyzers: Dict[Path, TypeAnalyzer] = {}  # file -> type analyzer
        # Memoizes ``get_reachable_functions`` per entry point. ``BehavioralCodeAnalyzer``
        # invokes the BFS twice for the same MCP entry point (once directly, once
        # transitively from ``analyze_parameter_flow_across_files``) — caching the
        # frozenset reuses the work and keeps successive calls O(1).
        self._reachable_cache: Dict[str, Set[str]] = {}
        self.logger = logging.getLogger(__name__)

    def add_file(self, file_path: Path, source_code: str) -> None:
        """Add a file to the analysis.

        Args:
            file_path: Path to the file
            source_code: Source code content
        """
        analyzer = PythonParser(file_path, source_code)
        try:
            analyzer.parse()
            self.analyzers[file_path] = analyzer

            # Run type analysis
            type_analyzer = TypeAnalyzer(analyzer)
            type_analyzer.analyze()
            self.type_analyzers[file_path] = type_analyzer

            # Extract function definitions and MCP entry points
            self._extract_python_functions(file_path, analyzer)

            # Extract imports
            self._extract_imports(file_path, analyzer)
        except Exception as e:
            self.logger.debug(f"Skipping unparseable file {file_path}: {e}")

    def _extract_python_functions(
        self, file_path: Path, analyzer: PythonParser
    ) -> None:
        """Extract function definitions and class methods from Python file.

        Args:
            file_path: File path
            analyzer: Python analyzer
        """
        # Get AST
        tree = analyzer.get_ast()

        # Extract top-level functions only (not methods inside classes)
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # Check if it's an MCP entry point
                is_mcp = self._is_mcp_entry_point(node)
                self.call_graph.add_function(node.name, node, file_path, is_mcp)

        # Extract class methods
        for node in tree.body:
            if isinstance(node, ast.ClassDef):
                class_name = node.name
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        # Add as ClassName.method_name
                        method_full_name = f"{class_name}.{item.name}"
                        self.call_graph.add_function(
                            method_full_name, item, file_path, is_mcp_entry=False
                        )

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
            if "." in decorator_name:
                parts = decorator_name.rsplit(".", 1)
                if len(parts) == 2 and parts[1] in ["tool", "prompt", "resource"]:
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

    def _extract_imports(self, file_path: Path, analyzer: PythonParser) -> None:
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

    def _extract_python_calls(self, file_path: Path, analyzer: PythonParser) -> None:
        """Extract function calls from Python file.

        Args:
            file_path: File path
            analyzer: Python analyzer
        """
        tree = analyzer.get_ast()

        # Extract calls from top-level functions
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                caller_name = f"{file_path}::{node.name}"
                self._extract_calls_from_function(
                    file_path, node, caller_name, analyzer
                )

        # Extract calls from class methods
        for node in tree.body:
            if isinstance(node, ast.ClassDef):
                class_name = node.name
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        caller_name = f"{file_path}::{class_name}.{item.name}"
                        self._extract_calls_from_function(
                            file_path, item, caller_name, analyzer
                        )

    def _extract_calls_from_function(
        self,
        file_path: Path,
        func_node: ast.FunctionDef,
        caller_name: str,
        analyzer: PythonParser,
    ) -> None:
        """Extract calls from a single function.

        Args:
            file_path: File path
            func_node: Function AST node
            caller_name: Full caller name
            analyzer: Python analyzer
        """
        # Walk the function body to find calls
        for node in ast.walk(func_node):
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

        Uses the ``CallGraph`` short-name index so lookups are O(candidates)
        instead of O(all functions). Same-file matches are preferred over
        global ones to preserve the ranking of the original linear scan.

        Args:
            file_path: File where call occurs
            call_name: Function call name (could be 'func' or 'obj.method')

        Returns:
            Full qualified name or None
        """
        file_prefix = str(file_path)

        def _pick(short: str) -> str | None:
            # Same-file matches take priority; fall through to any candidate
            # otherwise. Index hits are typically 1-3 entries, so the scan
            # cost is negligible vs. the previous O(N) full-functions walk.
            candidates = self.call_graph.get_functions_by_short_name(short)
            if not candidates:
                return None
            for fn in candidates:
                if fn.startswith(file_prefix):
                    return fn
            return candidates[0]

        # Handle method calls (e.g., 'processor.process' or 'DataProcessor.process')
        if "." in call_name:
            # Use type analyzer to resolve instance.method() to ClassName.method
            if file_path in self.type_analyzers:
                resolved = self.type_analyzers[file_path].resolve_method_call(call_name)
                if resolved:
                    hit = _pick(resolved)
                    if hit is not None:
                        return hit

            # Try to match the dotted name directly (covers ``ClassName.method``)
            hit = _pick(call_name)
            if hit is not None:
                return hit

            # Try the trailing two components (e.g. ``DataProcessor.process``)
            parts = call_name.split(".")
            if len(parts) >= 2:
                hit = _pick(".".join(parts[-2:]))
                if hit is not None:
                    return hit

            # Last-ditch: trailing component only (the index also stores
            # bare method names so this matches ``Class.method`` entries).
            hit = _pick(parts[-1])
            if hit is not None:
                return hit

        # Bare function name in the same file or globally
        hit = _pick(call_name)
        if hit is not None:
            return hit

        # Check imported files (covers ``from mod import func`` style usage)
        if file_path in self.import_map:
            for imported_file in self.import_map[file_path]:
                potential_name = f"{imported_file}::{call_name}"
                if potential_name in self.call_graph.functions:
                    return potential_name

        return None

    def _reachable_set(self, start_func: str) -> Set[str]:
        """Compute (and cache) the set of functions reachable from ``start_func``.

        BFS over the precomputed adjacency index in ``CallGraph``. The result
        is memoized per entry point because the alignment pipeline asks for
        reachability twice in succession (direct lookup, then again from
        ``analyze_parameter_flow_across_files``); without the cache the second
        call duplicates the entire traversal.
        """
        cached = self._reachable_cache.get(start_func)
        if cached is not None:
            return cached

        reachable: Set[str] = set()
        to_visit: List[str] = [start_func]

        while to_visit:
            current = to_visit.pop()
            if current in reachable:
                continue
            reachable.add(current)
            for callee in self.call_graph.get_callees(current):
                if callee not in reachable:
                    to_visit.append(callee)

        self._reachable_cache[start_func] = reachable
        return reachable

    def get_reachable_functions(self, start_func: str) -> List[str]:
        """Get all functions reachable from a starting function (REVERSED APPROACH).

        Args:
            start_func: Starting function (MCP entry point)

        Returns:
            List of reachable function names
        """
        return list(self._reachable_set(start_func))

    def get_reachable_from_entry_point(self, entry_point: str) -> Set[str]:
        """Get all functions reachable from an MCP entry point.

        Args:
            entry_point: MCP entry point function name

        Returns:
            Set of reachable function names
        """
        # Return a copy so callers can mutate without disturbing the cache.
        return set(self._reachable_set(entry_point))

    def analyze_parameter_flow_across_files(
        self, entry_point: str, param_names: List[str]
    ) -> Dict[str, Any]:
        """Analyze how parameters flow across files from an entry point.

        Walks the call graph forward from ``entry_point`` using the cached
        reachability set and the precomputed reverse-callers index, instead
        of scanning ``self.calls`` for every reachable function. Behaviour is
        equivalent: a function is "parameter-influenced" iff there exists a
        path from the entry point along caller→callee edges where every
        intermediate caller is itself parameter-influenced.

        Args:
            entry_point: MCP entry point function name
            param_names: Parameter names to track (reserved for future
                per-parameter granularity; the current heuristic propagates
                influence transitively from the entry point regardless).

        Returns:
            Dictionary with cross-file flow information
        """
        del param_names  # heuristic propagates influence transitively

        reachable = self._reachable_set(entry_point)

        # BFS forward from the entry point following only callees that are
        # themselves reachable. Each visited (caller, callee) edge is
        # considered for the cross-file flow report.
        param_influenced_funcs: Set[str] = set()
        cross_file_flows: List[Dict[str, Any]] = []

        queue: List[str] = [entry_point]
        seen_callers: Set[str] = {entry_point}
        while queue:
            caller = queue.pop()
            for callee in self.call_graph.get_callees(caller):
                if callee == caller or callee not in reachable:
                    continue
                param_influenced_funcs.add(callee)
                caller_file = caller.split("::")[0] if "::" in caller else "unknown"
                callee_file = callee.split("::")[0] if "::" in callee else "unknown"
                if caller_file != callee_file:
                    cross_file_flows.append(
                        {
                            "from_function": caller,
                            "to_function": callee,
                            "from_file": caller_file,
                            "to_file": callee_file,
                        }
                    )
                if callee not in seen_callers:
                    seen_callers.add(callee)
                    queue.append(callee)

        return {
            "reachable_functions": list(reachable),
            "param_influenced_functions": list(param_influenced_funcs),
            "cross_file_flows": cross_file_flows,
            "total_files_involved": len(
                set(f.split("::")[0] for f in reachable if "::" in f)
            ),
        }

    def get_all_files(self) -> List[Path]:
        """Get all files in the analysis.

        Returns:
            List of file paths
        """
        return list(self.analyzers.keys())
