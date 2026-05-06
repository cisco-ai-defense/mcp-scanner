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

"""Cross-file call graph analysis for tree-sitter languages.

Provides interprocedural analysis across TypeScript, JavaScript, Go, Java,
Kotlin, C#, Ruby, Rust, and PHP codebases.
"""

import logging
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from tree_sitter import Language, Parser, Node


# Module-level cache for tree-sitter ``Parser`` and ``Language`` instances.
# Constructing these is non-trivial (each call re-imports the language module
# and instantiates a fresh parser) and we previously paid that cost per file
# inside ``_get_parser`` and ``NativeAnalyzer._analyze_tree_sitter``. Caching
# them per language drops large-repo scan latency proportional to file count.
# Access is guarded by a lock because ``BehavioralCodeAnalyzer`` builds
# per-language call graphs concurrently via ``asyncio.to_thread``.
_PARSER_CACHE: Dict[str, Tuple["Parser", "Language"]] = {}
_PARSER_CACHE_LOCK = threading.Lock()


def _load_language(language: str) -> Optional["Language"]:
    """Import the tree-sitter language module for ``language`` and build a Language.

    Returns ``None`` if the corresponding ``tree_sitter_<language>`` package
    is not installed; callers fall back to the next-best analysis path. The
    PHP and TypeScript modules expose their grammar under language-specific
    factory names which is why they need a small shim.
    """
    try:
        if language == "javascript":
            import tree_sitter_javascript as mod
            return Language(mod.language())
        if language == "typescript":
            import tree_sitter_typescript as mod
            return Language(mod.language_typescript())
        if language == "go":
            import tree_sitter_go as mod
            return Language(mod.language())
        if language == "java":
            import tree_sitter_java as mod
            return Language(mod.language())
        if language == "kotlin":
            import tree_sitter_kotlin as mod
            return Language(mod.language())
        if language == "c_sharp":
            import tree_sitter_c_sharp as mod
            return Language(mod.language())
        if language == "ruby":
            import tree_sitter_ruby as mod
            return Language(mod.language())
        if language == "rust":
            import tree_sitter_rust as mod
            return Language(mod.language())
        if language == "php":
            import tree_sitter_php as mod
            return Language(mod.language_php())
    except ImportError:
        return None
    return None


def get_cached_parser(language: str) -> Optional["Parser"]:
    """Return a process-wide cached tree-sitter ``Parser`` for ``language``.

    Returns ``None`` when the language module isn't available so callers can
    short-circuit the whole tree-sitter path. The cache is intentionally
    populated lazily so the import cost is paid only for languages the user
    actually scans.
    """
    cached = _PARSER_CACHE.get(language)
    if cached is not None:
        return cached[0]
    with _PARSER_CACHE_LOCK:
        cached = _PARSER_CACHE.get(language)
        if cached is not None:
            return cached[0]
        lang = _load_language(language)
        if lang is None:
            return None
        parser = Parser(lang)
        _PARSER_CACHE[language] = (parser, lang)
        return parser


@dataclass
class TSCallGraph:
    """Call graph for tree-sitter languages.

    Mirrors the indices added to the Python ``CallGraph`` class so reachability
    queries, name resolution, and fan-out edges all run in O(out-degree)
    instead of O(edges). The duplicate-edge guard also keeps memory footprint
    bounded when the same call site is encountered by both the function-context
    extractor and the cross-file analyzer.
    """

    functions: Dict[str, Node] = field(default_factory=dict)  # full_name -> function node
    calls: List[Tuple[str, str]] = field(default_factory=list)  # (caller, callee) pairs
    entry_points: Set[str] = field(default_factory=set)  # Entry point functions

    # Performance indices: forward / reverse adjacency + short-name lookup.
    _callees: Dict[str, List[str]] = field(default_factory=lambda: defaultdict(list))
    _callers: Dict[str, List[str]] = field(default_factory=lambda: defaultdict(list))
    _edges: Set[Tuple[str, str]] = field(default_factory=set)
    _functions_by_short: Dict[str, List[str]] = field(
        default_factory=lambda: defaultdict(list)
    )
    # Guards index mutations when ``add_file`` is invoked concurrently by
    # ``BehavioralCodeAnalyzer``'s thread pool. The lock is held only for
    # the brief index updates, not for the heavy parser work.
    _mutation_lock: threading.Lock = field(default_factory=threading.Lock)

    def add_function(self, name: str, node: Node, file_path: Path, is_entry: bool = False) -> None:
        """Add a function definition."""
        full_name = f"{file_path}::{name}"
        with self._mutation_lock:
            if full_name in self.functions:
                if is_entry:
                    self.entry_points.add(full_name)
                return
            self.functions[full_name] = node
            if is_entry:
                self.entry_points.add(full_name)
            # Mirror the Python graph's dual-key indexing so resolver lookups
            # can match both ``Class.method`` and the bare ``method``.
            self._functions_by_short[name].append(full_name)
            if "." in name:
                self._functions_by_short[name.rsplit(".", 1)[-1]].append(full_name)

    def add_call(self, caller: str, callee: str) -> None:
        """Add a function call edge (deduped)."""
        edge = (caller, callee)
        with self._mutation_lock:
            if edge in self._edges:
                return
            self._edges.add(edge)
            self.calls.append(edge)
            self._callees[caller].append(callee)
            self._callers[callee].append(caller)

    def get_callees(self, func_name: str) -> List[str]:
        """Get functions called by a function."""
        callees = self._callees.get(func_name)
        return list(callees) if callees else []

    def get_callers(self, func_name: str) -> List[str]:
        """Get functions that call a function."""
        callers = self._callers.get(func_name)
        return list(callers) if callers else []

    def get_functions_by_short_name(self, short_name: str) -> List[str]:
        """Return all fully-qualified function names matching ``short_name``."""
        candidates = self._functions_by_short.get(short_name)
        return list(candidates) if candidates else []


class TreeSitterCallGraphAnalyzer:
    """Cross-file call graph analysis for tree-sitter languages.
    
    Supports: TypeScript, JavaScript, Go, Java, Kotlin, C#, Ruby, Rust, PHP
    """
    
    # Function node types per language
    FUNCTION_TYPES = {
        "javascript": {"function_declaration", "function_expression", "arrow_function", "method_definition"},
        "typescript": {"function_declaration", "function_expression", "arrow_function", "method_definition"},
        "go": {"function_declaration", "method_declaration"},
        "java": {"method_declaration", "constructor_declaration"},
        "kotlin": {"function_declaration", "secondary_constructor"},
        "c_sharp": {"method_declaration", "constructor_declaration", "local_function_statement"},
        "ruby": {"method", "singleton_method"},
        "rust": {"function_item"},
        "php": {"function_definition", "method_declaration"},
    }
    
    # Call expression types per language
    CALL_TYPES = {
        "javascript": {"call_expression", "new_expression"},
        "typescript": {"call_expression", "new_expression"},
        "go": {"call_expression"},
        "java": {"method_invocation", "object_creation_expression"},
        "kotlin": {"call_expression"},
        "c_sharp": {"invocation_expression", "object_creation_expression"},
        "ruby": {"call", "method_call"},
        "rust": {"call_expression", "macro_invocation"},
        "php": {"function_call_expression", "member_call_expression", "scoped_call_expression"},
    }
    
    # Import node types per language
    IMPORT_TYPES = {
        "javascript": {"import_statement", "call_expression"},  # call_expression for require()
        "typescript": {"import_statement", "call_expression"},
        "go": {"import_declaration"},
        "java": {"import_declaration"},
        "kotlin": {"import_header"},
        "c_sharp": {"using_directive"},
        "ruby": {"call"},  # require/require_relative
        "rust": {"use_declaration"},
        "php": {"namespace_use_declaration"},
    }
    
    def __init__(self, language: str):
        """Initialize call graph analyzer."""
        self.language = language
        self.call_graph = TSCallGraph()
        self.files: Dict[Path, tuple] = {}  # file_path -> (tree, source_bytes)
        self.import_map: Dict[Path, List[str]] = {}
        # Reachability cache; mirrors the Python ``CallGraphAnalyzer`` so the
        # second BFS over the same entry point during cross-file enrichment
        # is a dictionary lookup.
        self._reachable_cache: Dict[str, Set[str]] = {}
        self.logger = logging.getLogger(__name__)

    def _get_parser(self) -> Optional[Parser]:
        """Get the cached tree-sitter parser for this language.

        Delegates to the module-level ``get_cached_parser`` so all analyzers
        for the same language share one ``Parser``/``Language`` pair instead
        of paying the import + factory cost per ``add_file``.
        """
        return get_cached_parser(self.language)
    
    def add_file(self, file_path: Path, source_code: str) -> bool:
        """Add a file to the analysis."""
        parser = self._get_parser()
        if not parser:
            return False
        
        try:
            source_bytes = source_code.encode("utf-8")
            tree = parser.parse(source_bytes)
            self.files[file_path] = (tree, source_bytes)
            
            # Extract functions
            self._extract_functions(file_path, tree.root_node, source_bytes)
            
            # Extract imports
            self._extract_imports(file_path, tree.root_node, source_bytes)
            
            return True
        except Exception as e:
            self.logger.debug(f"Failed to parse {file_path}: {e}")
            return False
    
    def _extract_functions(self, file_path: Path, root: Node, source_bytes: bytes, class_name: str = "") -> None:
        """Extract function definitions from AST."""
        func_types = self.FUNCTION_TYPES.get(self.language, set())
        class_types = {"class_declaration", "class", "struct_item", "impl_item", "object_declaration"}
        
        for child in root.children:
            if child.type in func_types:
                name = self._get_function_name(child, source_bytes)
                if class_name:
                    name = f"{class_name}.{name}"
                self.call_graph.add_function(name, child, file_path)
            
            elif child.type in class_types:
                # Get class name and recurse
                name_node = child.child_by_field_name("name")
                if name_node:
                    cls_name = source_bytes[name_node.start_byte:name_node.end_byte].decode("utf-8")
                    self._extract_functions(file_path, child, source_bytes, cls_name)
            
            # Recurse into other containers
            elif child.type in ("program", "source_file", "module", "namespace_declaration", 
                               "class_body", "interface_body", "block"):
                self._extract_functions(file_path, child, source_bytes, class_name)
    
    def _get_function_name(self, node: Node, source_bytes: bytes) -> str:
        """Get function name from AST node."""
        name_node = node.child_by_field_name("name")
        if name_node:
            return source_bytes[name_node.start_byte:name_node.end_byte].decode("utf-8")
        
        # For arrow functions assigned to variables
        if node.type == "arrow_function" and node.parent:
            if node.parent.type == "variable_declarator":
                name_node = node.parent.child_by_field_name("name")
                if name_node:
                    return source_bytes[name_node.start_byte:name_node.end_byte].decode("utf-8")
        
        return "<anonymous>"
    
    def _extract_imports(self, file_path: Path, root: Node, source_bytes: bytes) -> None:
        """Extract import statements."""
        imports = []
        import_types = self.IMPORT_TYPES.get(self.language, set())
        
        def visit(node: Node):
            if node.type in import_types:
                import_text = source_bytes[node.start_byte:node.end_byte].decode("utf-8")
                imports.append(import_text)
            
            for child in node.children:
                visit(child)
        
        visit(root)
        self.import_map[file_path] = imports
    
    def build_call_graph(self) -> TSCallGraph:
        """Build the complete call graph."""
        for file_path, (tree, source_bytes) in self.files.items():
            self._extract_calls(file_path, tree.root_node, source_bytes)
        
        return self.call_graph
    
    def _extract_calls(self, file_path: Path, root: Node, source_bytes: bytes, current_func: str = "") -> None:
        """Extract function calls from AST."""
        func_types = self.FUNCTION_TYPES.get(self.language, set())
        call_types = self.CALL_TYPES.get(self.language, set())
        
        for child in root.children:
            # Track current function context
            if child.type in func_types:
                func_name = self._get_function_name(child, source_bytes)
                full_name = f"{file_path}::{func_name}"
                self._extract_calls(file_path, child, source_bytes, full_name)
            
            # Extract calls
            elif child.type in call_types and current_func:
                callee_name = self._get_call_name(child, source_bytes)
                if callee_name:
                    # Try to resolve to full name
                    resolved = self._resolve_call(file_path, callee_name)
                    self.call_graph.add_call(current_func, resolved or callee_name)
            
            else:
                self._extract_calls(file_path, child, source_bytes, current_func)
    
    def _get_call_name(self, node: Node, source_bytes: bytes) -> str:
        """Get the name of a function call."""
        func = node.child_by_field_name("function") or node.child_by_field_name("name")
        if func:
            return source_bytes[func.start_byte:func.end_byte].decode("utf-8")
        return ""
    
    def _resolve_call(self, file_path: Path, call_name: str) -> Optional[str]:
        """Resolve a call to its full qualified name using the short-name index.

        Same-file matches still take precedence; this just removes the O(N)
        scan that the previous two-pass linear search performed for every
        call site in every file.
        """
        candidates = self.call_graph.get_functions_by_short_name(call_name)
        if not candidates:
            return None
        file_prefix = str(file_path)
        for fn in candidates:
            if fn.startswith(file_prefix):
                return fn
        return candidates[0]

    def _reachable_set(self, start_func: str) -> Set[str]:
        """Compute and cache the BFS-reachable set from ``start_func``."""
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
        """Get all functions reachable from a starting function."""
        return list(self._reachable_set(start_func))

    def analyze_cross_file_flows(self, entry_point: str, param_names: List[str]) -> Dict[str, Any]:
        """Analyze parameter flow across files from an entry point.

        Walks forward through the call graph using the precomputed adjacency
        index instead of scanning every edge for every reachable function.
        """
        del param_names  # heuristic propagates influence transitively

        reachable = self._reachable_set(entry_point)

        param_influenced: Set[str] = set()
        cross_file_flows: List[Dict[str, Any]] = []
        queue: List[str] = [entry_point]
        seen_callers: Set[str] = {entry_point}
        while queue:
            caller = queue.pop()
            for callee in self.call_graph.get_callees(caller):
                if callee == caller or callee not in reachable:
                    continue
                param_influenced.add(callee)
                caller_file = caller.split("::")[0] if "::" in caller else "unknown"
                callee_file = callee.split("::")[0] if "::" in callee else "unknown"
                if caller_file != callee_file:
                    cross_file_flows.append({
                        "from_function": caller,
                        "to_function": callee,
                        "from_file": caller_file,
                        "to_file": callee_file,
                    })
                if callee not in seen_callers:
                    seen_callers.add(callee)
                    queue.append(callee)

        return {
            "reachable_functions": list(reachable),
            "param_influenced_functions": list(param_influenced),
            "cross_file_flows": cross_file_flows,
            "total_files_involved": len(
                set(f.split("::")[0] for f in reachable if "::" in f)
            ),
        }
