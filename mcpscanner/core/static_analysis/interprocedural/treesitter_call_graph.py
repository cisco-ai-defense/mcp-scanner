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

import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from tree_sitter import Language, Parser, Node

from ....utils.log_format import sanitize_log_value, truncate
from ....utils.logging_config import get_logger


_MCP_DECORATOR_RE = re.compile(
    r"(?:"
    r"@\w*\.(?:tool|prompt|resource)\b"
    r"|@(?:tool|prompt|resource)\b"
    r"|@Mcp(?:Tool|Resource|Prompt)\b"
    r"|#\[Mcp(?:Tool|Resource|Prompt)\b"
    r"|@Tool\b"
    r"|registerTool\b|registerPrompt\b|registerResource\b"
    r")",
    re.IGNORECASE,
)


def _qualified_name_matches(func_full: str, call_name: str) -> bool:
    """
    Determine whether a call name matches a fully qualified function name.
    
    Parameters:
        func_full (str): Fully qualified function name, optionally including a file path.
        call_name (str): Function or method name used at the call site.
    
    Returns:
        bool: `True` if the names match, `False` otherwise.
    """
    qualified = func_full.split("::", 1)[-1] if "::" in func_full else func_full
    short = call_name.split(".")[-1]
    return (
        qualified == call_name
        or qualified.endswith(f".{call_name}")
        or qualified == short
        or qualified.endswith(f".{short}")
    )


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
        self.logger = get_logger(__name__)
        self._skipped_files: int = 0
        self._added_files: int = 0
        self._language_load_warned: bool = False

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
        except ImportError as exc:
            if not self._language_load_warned:
                self._language_load_warned = True
                self.logger.warning(
                    "static_interproc treesitter language_module_missing "
                    "language=%s error_type=%s error=%s",
                    self.language,
                    type(exc).__name__,
                    truncate(exc, 200),
                )
            return None
    
    def add_file(self, file_path: Path, source_code: str) -> bool:
        """Add a file to the analysis."""
        parser = self._get_parser()
        if not parser:
            self._skipped_files += 1
            return False

        try:
            source_bytes = source_code.encode("utf-8")
            tree = parser.parse(source_bytes)
            self.files[file_path] = (tree, source_bytes)
            
            # Extract functions
            self._extract_functions(file_path, tree.root_node, source_bytes)
            
            # Extract imports
            self._extract_imports(file_path, tree.root_node, source_bytes)

            self._added_files += 1
            return True
        except Exception as e:
            self._skipped_files += 1
            self.logger.debug(
                "static_interproc treesitter parse_failed file=%s language=%s "
                "error_type=%s error=%s",
                sanitize_log_value(file_path),
                self.language,
                type(e).__name__,
                truncate(e, 200),
            )
            return False
    
    def _extract_functions(self, file_path: Path, root: Node, source_bytes: bytes, class_name: str = "") -> None:
        """Extract function definitions from an abstract syntax tree and add them to the call graph.
        
        Functions defined within classes are recorded with qualified names. Functions marked with supported MCP decorators or attributes are recorded as entry points.
        """
        func_types = self.FUNCTION_TYPES.get(self.language, set())
        class_types = {"class_declaration", "class", "struct_item", "impl_item", "object_declaration"}
        container_types = {
            "program",
            "source_file",
            "module",
            "namespace_declaration",
            "class_body",
            "interface_body",
            "declaration_list",
            "body_statement",
            "block",
            "export_statement",
            "export_declaration",
            "default_export_declaration",
        }

        for child in root.children:
            if child.type in func_types:
                name = self._get_function_name(child, source_bytes)
                if class_name:
                    name = f"{class_name}.{name}"
                self.call_graph.add_function(
                    name,
                    child,
                    file_path,
                    is_entry=self._is_mcp_entry_point(child, source_bytes),
                )

            elif child.type in class_types:
                # Get class name and recurse
                name_node = (
                    child.child_by_field_name("name")
                    or child.child_by_field_name("type")
                    or child.child_by_field_name("constant")
                )
                if name_node:
                    cls_name = source_bytes[name_node.start_byte:name_node.end_byte].decode("utf-8")
                    self._extract_functions(file_path, child, source_bytes, cls_name)

            # Recurse into other containers
            elif child.type in container_types:
                self._extract_functions(file_path, child, source_bytes, class_name)
    
    @staticmethod
    def _node_text(node: Node, source_bytes: bytes) -> str:
        """Extract the source text represented by a syntax tree node.
        
        Parameters:
        	node (Node): Syntax tree node whose source range is extracted.
        	source_bytes (bytes): Source file contents containing the node.
        
        Returns:
        	str: UTF-8 decoded source text for the node.
        """
        return source_bytes[node.start_byte : node.end_byte].decode("utf-8")

    def _decorator_texts_for_function(self, node: Node, source_bytes: bytes) -> list[str]:
        """
        Collect decorator and attribute text associated with a function node.
        
        Parameters:
            node (Node): Function syntax node whose annotations are inspected.
            source_bytes (bytes): Source bytes used to extract annotation text.
        
        Returns:
            list[str]: Text of decorators, attributes, and modifiers associated with the function.
        """
        texts: list[str] = []
        for child in node.children:
            if child.type in {"attribute_list", "modifiers"}:
                texts.append(self._node_text(child, source_bytes))

        parent = node.parent
        if parent is not None:
            for child in parent.children:
                if child is node:
                    break
                if child.type in {"decorator", "attribute_list", "modifiers"}:
                    texts.append(self._node_text(child, source_bytes))

        prev = node.prev_sibling
        while prev is not None:
            if prev.type in {"decorator", "attribute_list", "modifiers", "call"}:
                texts.append(self._node_text(prev, source_bytes))
                break
            if prev.type not in {"comment", "line_comment", "block_comment"}:
                break
            prev = prev.prev_sibling
        return texts

    def _is_mcp_entry_point(self, node: Node, source_bytes: bytes) -> bool:
        """Determine whether a function has an MCP entry-point decorator or annotation.
        
        Parameters:
            node (Node): The function syntax-tree node to inspect.
            source_bytes (bytes): The source text containing the function.
        
        Returns:
            bool: `True` if the function has an MCP entry-point marker, `False` otherwise.
        """
        for text in self._decorator_texts_for_function(node, source_bytes):
            if _MCP_DECORATOR_RE.search(text):
                return True
        return False

    def _get_function_name(self, node: Node, source_bytes: bytes) -> str:
        """
        Extract the function name represented by an AST node.
        
        Parameters:
        	node (Node): AST node representing the function.
        	source_bytes (bytes): Source bytes used to read the function name.
        
        Returns:
        	str: The declared or variable-assigned function name, or "<anonymous>" when no name is available.
        """
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
        build_start = time.perf_counter()
        for file_path, (tree, source_bytes) in self.files.items():
            self._extract_calls(file_path, tree.root_node, source_bytes)

        functions = len(self.call_graph.functions)
        calls = len(self.call_graph.calls)
        self.logger.info(
            "static_interproc treesitter call_graph_built language=%s "
            "files=%d added=%d skipped=%d functions=%d calls=%d duration_ms=%d",
            self.language,
            len(self.files),
            self._added_files,
            self._skipped_files,
            functions,
            calls,
            int((time.perf_counter() - build_start) * 1000),
        )
        return self.call_graph
    
    _CLASS_TYPES = frozenset(
        {"class_declaration", "class", "struct_item", "impl_item", "object_declaration"}
    )
    _CONTAINER_TYPES = frozenset(
        {
            "program",
            "source_file",
            "module",
            "namespace_declaration",
            "class_body",
            "interface_body",
            "declaration_list",
            "body_statement",
            "block",
            "export_statement",
            "export_declaration",
            "default_export_declaration",
        }
    )

    def _extract_calls(
        self,
        file_path: Path,
        root: Node,
        source_bytes: bytes,
        current_func: str = "",
        class_name: str = "",
    ) -> None:
        """Extract function-call relationships from an abstract syntax tree and add them to the call graph.
        
        Parameters:
        	file_path (Path): Path of the file containing the syntax tree.
        	root (Node): Root node of the syntax tree or subtree to traverse.
        	source_bytes (bytes): Source bytes used to resolve function and call names.
        	current_func (str): Fully qualified name of the function currently being traversed.
        	class_name (str): Name of the enclosing class, if applicable.
        """
        func_types = self.FUNCTION_TYPES.get(self.language, set())
        call_types = self.CALL_TYPES.get(self.language, set())

        for child in root.children:
            if child.type in func_types:
                func_name = self._get_function_name(child, source_bytes)
                if class_name:
                    func_name = f"{class_name}.{func_name}"
                full_name = f"{file_path}::{func_name}"
                self._extract_calls(
                    file_path, child, source_bytes, full_name, class_name
                )

            elif child.type in call_types and current_func:
                callee_name = self._get_call_name(child, source_bytes)
                if callee_name:
                    resolved = self._resolve_call(file_path, callee_name)
                    self.call_graph.add_call(current_func, resolved or callee_name)

            elif child.type in self._CLASS_TYPES:
                name_node = (
                    child.child_by_field_name("name")
                    or child.child_by_field_name("type")
                    or child.child_by_field_name("constant")
                )
                if name_node:
                    cls_name = source_bytes[
                        name_node.start_byte : name_node.end_byte
                    ].decode("utf-8")
                    self._extract_calls(
                        file_path, child, source_bytes, current_func, cls_name
                    )
                else:
                    self._extract_calls(
                        file_path, child, source_bytes, current_func, class_name
                    )

            elif child.type in self._CONTAINER_TYPES:
                self._extract_calls(
                    file_path, child, source_bytes, current_func, class_name
                )

            else:
                self._extract_calls(
                    file_path, child, source_bytes, current_func, class_name
                )
    
    def _get_call_name(self, node: Node, source_bytes: bytes) -> str:
        """
        Extract the qualified name used to identify a function call.
        
        Parameters:
        	node (Node): The syntax tree node representing the call.
        	source_bytes (bytes): Source code bytes used to recover call-name text.
        
        Returns:
        	str: The function, method, or qualified call name, or an empty string when no name can be identified.
        """
        if node.type == "member_call_expression":
            obj = node.child_by_field_name("object")
            name = node.child_by_field_name("name")
            if obj is not None and name is not None:
                obj_text = source_bytes[obj.start_byte : obj.end_byte].decode("utf-8")
                name_text = source_bytes[name.start_byte : name.end_byte].decode("utf-8")
                return f"{obj_text}->{name_text}"

        receiver = node.child_by_field_name("receiver")
        method = node.child_by_field_name("method")
        if receiver is not None and method is not None:
            recv = source_bytes[receiver.start_byte : receiver.end_byte].decode("utf-8")
            meth = source_bytes[method.start_byte : method.end_byte].decode("utf-8")
            if meth == "send":
                first_arg = self._first_call_argument_name(node, source_bytes)
                if first_arg:
                    return f"{recv}.send({first_arg})"
            return f"{recv}.{meth}"

        func = (
            node.child_by_field_name("function")
            or node.child_by_field_name("name")
            or (method if method is not None else None)
        )
        if func:
            return source_bytes[func.start_byte : func.end_byte].decode("utf-8")

        skip_types = {
            "(",
            ")",
            ";",
            "argument_list",
            "arguments",
            "value_arguments",
            "type_arguments",
        }
        for child in node.children:
            if child.type in skip_types:
                continue
            text = source_bytes[child.start_byte : child.end_byte].decode("utf-8").strip()
            if text:
                return text
        return ""
    
    @staticmethod
    def _first_call_argument_name(node: Node, source_bytes: bytes) -> str | None:
        """Extract the name of the first identifier argument from a call node.
        
        Parameters:
        	node (Node): The syntax tree node representing the call.
        	source_bytes (bytes): The source bytes used to decode the identifier text.
        
        Returns:
        	str | None: The first identifier argument name, or `None` when no identifier argument is present.
        """
        args = node.child_by_field_name("arguments") or node.child_by_field_name(
            "argument_list"
        )
        if args is None:
            return None
        for child in args.children:
            if child.type in {"(", ")", ",", ";"}:
                continue
            if child.type == "argument":
                inner = child.child_by_field_name("value") or (
                    child.children[0] if child.children else None
                )
                if inner is not None and inner.type == "identifier":
                    return source_bytes[inner.start_byte : inner.end_byte].decode("utf-8")
            if child.type == "identifier":
                return source_bytes[child.start_byte : child.end_byte].decode("utf-8")
        return None

    def _resolve_call(self, file_path: Path, call_name: str) -> Optional[str]:
        """Resolve a call name to a matching fully qualified function name.
        
        Parameters:
            file_path (Path): Path of the file containing the call.
            call_name (str): Name of the called function.
        
        Returns:
            Optional[str]: The matching function name, preferring a function from the same file; otherwise, `None` when no unique match exists.
        """
        same_file: list[str] = []
        all_matches: list[str] = []
        for func_name in self.call_graph.functions:
            if not _qualified_name_matches(func_name, call_name):
                continue
            all_matches.append(func_name)
            if func_name.startswith(str(file_path)):
                same_file.append(func_name)

        if len(same_file) == 1:
            return same_file[0]
        if len(same_file) > 1:
            return same_file[0]
        if len(all_matches) == 1:
            return all_matches[0]
        return None
    
    def get_reachable_functions(self, start_func: str) -> List[str]:
        """
        Determine which functions can be reached from a starting function.
        
        Parameters:
            start_func (str): Fully qualified name of the function from which traversal begins.
        
        Returns:
            List[str]: Names of the starting function and all functions reachable through call edges.
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
