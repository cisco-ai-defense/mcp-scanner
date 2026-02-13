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
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from tree_sitter import Language, Parser, Node


@dataclass
class TSCallGraph:
    """Call graph for tree-sitter languages."""
    
    functions: Dict[str, Node] = field(default_factory=dict)  # full_name -> function node
    calls: List[tuple] = field(default_factory=list)  # (caller, callee) pairs
    entry_points: Set[str] = field(default_factory=set)  # Entry point functions
    
    def add_function(self, name: str, node: Node, file_path: Path, is_entry: bool = False) -> None:
        """Add a function definition."""
        full_name = f"{file_path}::{name}"
        self.functions[full_name] = node
        if is_entry:
            self.entry_points.add(full_name)
    
    def add_call(self, caller: str, callee: str) -> None:
        """Add a function call edge."""
        self.calls.append((caller, callee))
    
    def get_callees(self, func_name: str) -> List[str]:
        """Get functions called by a function."""
        return [callee for caller, callee in self.calls if caller == func_name]
    
    def get_callers(self, func_name: str) -> List[str]:
        """Get functions that call a function."""
        return [caller for caller, callee in self.calls if callee == func_name]


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
        self.logger = logging.getLogger(__name__)
        
        self._parser: Optional[Parser] = None
        self._lang: Optional[Language] = None
    
    def _get_parser(self) -> Optional[Parser]:
        """Get or create parser for the language."""
        if self._parser:
            return self._parser
        
        try:
            if self.language == "javascript":
                import tree_sitter_javascript as mod
                self._lang = Language(mod.language())
            elif self.language == "typescript":
                import tree_sitter_typescript as mod
                self._lang = Language(mod.language_typescript())
            elif self.language == "go":
                import tree_sitter_go as mod
                self._lang = Language(mod.language())
            elif self.language == "java":
                import tree_sitter_java as mod
                self._lang = Language(mod.language())
            elif self.language == "kotlin":
                import tree_sitter_kotlin as mod
                self._lang = Language(mod.language())
            elif self.language == "c_sharp":
                import tree_sitter_c_sharp as mod
                self._lang = Language(mod.language())
            elif self.language == "ruby":
                import tree_sitter_ruby as mod
                self._lang = Language(mod.language())
            elif self.language == "rust":
                import tree_sitter_rust as mod
                self._lang = Language(mod.language())
            elif self.language == "php":
                import tree_sitter_php as mod
                self._lang = Language(mod.language_php())
            else:
                return None
            
            self._parser = Parser(self._lang)
            return self._parser
        except ImportError:
            return None
    
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
        """Resolve a call to its full qualified name."""
        # Check same file
        for func_name in self.call_graph.functions:
            if func_name.endswith(f"::{call_name}"):
                if func_name.startswith(str(file_path)):
                    return func_name
        
        # Check all files (for cross-file calls)
        for func_name in self.call_graph.functions:
            if func_name.endswith(f"::{call_name}"):
                return func_name
        
        return None
    
    def get_reachable_functions(self, start_func: str) -> List[str]:
        """Get all functions reachable from a starting function."""
        reachable = set()
        to_visit = [start_func]
        visited = set()
        
        while to_visit:
            current = to_visit.pop()
            if current in visited:
                continue
            
            visited.add(current)
            reachable.add(current)
            
            for callee in self.call_graph.get_callees(current):
                if callee not in visited:
                    to_visit.append(callee)
        
        return list(reachable)
    
    def analyze_cross_file_flows(self, entry_point: str, param_names: List[str]) -> Dict[str, Any]:
        """Analyze parameter flow across files from an entry point."""
        reachable = self.get_reachable_functions(entry_point)
        
        param_influenced = set()
        cross_file_flows = []
        
        for func_name in reachable:
            if func_name == entry_point:
                continue
            
            for caller, callee in self.call_graph.calls:
                if callee == func_name and (caller == entry_point or caller in param_influenced):
                    param_influenced.add(func_name)
                    
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
            "param_influenced_functions": list(param_influenced),
            "cross_file_flows": cross_file_flows,
            "total_files_involved": len(set(f.split("::")[0] for f in reachable if "::" in f)),
        }
