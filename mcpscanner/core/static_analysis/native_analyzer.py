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

"""Native Code Analyzer - AST-based multi-language analyzer.

This module provides code analyzer that works when the primary
ContextExtractor fails or cannot understand the code structure.
It supports MCP servers written in multiple languages.

Supported languages and MCP SDK patterns:
- Python (via built-in ast module): @mcp.tool(), @mcp.resource(), @mcp.prompt()
- TypeScript/JavaScript (via tree-sitter): server.registerTool(), server.tool()
- Go (via tree-sitter): mcp.AddTool(server, &mcp.Tool{...}, handler)
- Java/Spring (via tree-sitter): @Tool, @ToolParam annotations on @Service classes
- Kotlin (via tree-sitter): server.addTool(name, description, inputSchema) { handler }
- C#/.NET (via tree-sitter): [McpServerTool], [Description] on [McpServerToolType] classes
- Rust (via tree-sitter): #[tool], #[tool_router] macros (rmcp crate)
- Ruby (via tree-sitter): # @tool comment annotations
- PHP (via tree-sitter): @Tool annotations in docblocks
- Swift (via tree-sitter): General function analysis

Key features:
- Pure AST extraction - NO hardcoded patterns
- Extracts ALL code elements and lets LLM analyze them
- Comprehensive taint tracking for security analysis
- Cross-language security operation detection (command injection, SQL injection, etc.)
- Outputs the same FunctionContext format as the primary analyzer
- Works regardless of decorator patterns used
"""

import ast
import logging
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union

from .context_extractor import FunctionContext
from .parser.python_parser import PythonParser
from .dataflow.forward_analysis import ForwardDataflowAnalysis
from .dataflow.treesitter_analysis import TreeSitterDataflowAnalysis
from .taint.tracker import TaintStatus


# Simple TaintInfo for fallback (when full analysis fails)
@dataclass
class TaintInfo:
    """Simple taint information for fallback analysis."""
    status: TaintStatus = TaintStatus.UNTAINTED
    sources: Set[str] = field(default_factory=set)
    
    def is_tainted(self) -> bool:
        return self.status == TaintStatus.TAINTED
    
    def merge(self, other: "TaintInfo") -> "TaintInfo":
        """Merge two taint infos (union of taints)."""
        if self.status == TaintStatus.TAINTED or other.status == TaintStatus.TAINTED:
            return TaintInfo(
                status=TaintStatus.TAINTED,
                sources=self.sources | other.sources
            )
        return TaintInfo(status=self.status, sources=self.sources.copy())

# Tree-sitter imports - each language is optional
from tree_sitter import Language, Parser, Node
TREE_SITTER_AVAILABLE = True

# Language modules - imported lazily
_LANGUAGE_MODULES: Dict[str, Any] = {}

def _get_language_module(lang: str) -> Optional[Any]:
    """Lazily import tree-sitter language module."""
    if lang in _LANGUAGE_MODULES:
        return _LANGUAGE_MODULES[lang]
    
    try:
        if lang == "javascript":
            import tree_sitter_javascript as mod
        elif lang == "typescript":
            import tree_sitter_typescript as mod
        elif lang == "go":
            import tree_sitter_go as mod
        elif lang == "java":
            import tree_sitter_java as mod
        elif lang == "kotlin":
            import tree_sitter_kotlin as mod
        elif lang == "swift":
            import tree_sitter_swift as mod
        elif lang == "c_sharp":
            import tree_sitter_c_sharp as mod
        elif lang == "ruby":
            import tree_sitter_ruby as mod
        elif lang == "rust":
            import tree_sitter_rust as mod
        elif lang == "php":
            import tree_sitter_php as mod
        else:
            return None
        _LANGUAGE_MODULES[lang] = mod
        return mod
    except ImportError:
        _LANGUAGE_MODULES[lang] = None
        return None


@dataclass
class NativeAnalysisResult:
    """Result of native analysis for a single unit."""

    success: bool
    language: str
    functions: List[FunctionContext] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    partial: bool = False


class NativeAnalyzer:
    """Native AST-based code analyzer - pure extraction, no hardcoded patterns.

    This analyzer extracts ALL code elements from source code via AST parsing.
    It does NOT apply any hardcoded security patterns - that's left to the LLM.

    Supports:
    - Python: Uses built-in ast module with full dataflow analysis
    - TypeScript/JavaScript/Go/Java/Kotlin/C#/Ruby/Rust/PHP: Uses tree-sitter with dataflow

    The output format matches FunctionContext for compatibility with
    the existing analysis pipeline.
    
    Key difference from basic NativeAnalyzer:
    - Performs taint tracking from function parameters
    - Detects security-relevant operations via dataflow (not hardcoded patterns)
    - Tracks parameter flows to calls, returns, and external operations
    """

    # File extension to language mapping
    EXTENSION_MAP = {
        # Python
        ".py": "python", ".pyw": "python",
        # TypeScript
        ".ts": "typescript", ".tsx": "typescript", ".mts": "typescript", ".cts": "typescript",
        # JavaScript
        ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
        # Go
        ".go": "go",
        # Java
        ".java": "java",
        # Kotlin
        ".kt": "kotlin", ".kts": "kotlin",
        # Swift
        ".swift": "swift",
        # C#
        ".cs": "c_sharp",
        # Ruby
        ".rb": "ruby", ".rake": "ruby", ".gemspec": "ruby",
        # Rust
        ".rs": "rust",
        # PHP
        ".php": "php", ".phtml": "php",
    }

    # Function node types per language (for tree-sitter)
    FUNCTION_NODE_TYPES = {
        "javascript": {"function_declaration", "function_expression", "arrow_function", "method_definition"},
        "typescript": {"function_declaration", "function_expression", "arrow_function", "method_definition"},
        "go": {"function_declaration", "method_declaration"},
        "java": {"method_declaration", "constructor_declaration"},
        "kotlin": {"function_declaration", "secondary_constructor", "primary_constructor", "lambda_literal", "anonymous_function"},
        "swift": {"function_declaration", "initializer_declaration"},
        "c_sharp": {"method_declaration", "constructor_declaration", "local_function_statement"},
        "ruby": {"method", "singleton_method"},
        "rust": {"function_item", "impl_item"},
        "php": {"function_definition", "method_declaration"},
    }

    # Class node types per language
    CLASS_NODE_TYPES = {
        "javascript": {"class_declaration"},
        "typescript": {"class_declaration"},
        "go": {"type_declaration"},
        "java": {"class_declaration", "interface_declaration"},
        "kotlin": {"class_declaration", "object_declaration"},
        "swift": {"class_declaration", "struct_declaration"},
        "c_sharp": {"class_declaration", "struct_declaration", "interface_declaration"},
        "ruby": {"class", "module"},
        "rust": {"struct_item", "impl_item"},
        "php": {"class_declaration", "interface_declaration"},
    }

    def __init__(self, source_code: str, file_path: str = "unknown"):
        """Initialize native analyzer.

        Args:
            source_code: Source code to analyze
            file_path: Path to source file (used for language detection)
        """
        self.source_code = source_code
        self.source_bytes = source_code.encode("utf-8")
        self.file_path = Path(file_path)
        self.lines = source_code.split("\n")
        self.logger = logging.getLogger(__name__)
        self.language = self._detect_language()
        
        # Taint tracking state (reset per function)
        self._taint_env: Dict[str, TaintInfo] = {}

    def _detect_language(self) -> str:
        """Detect programming language from file extension."""
        ext = self.file_path.suffix.lower()

        # Check extension map first
        if ext in self.EXTENSION_MAP:
            return self.EXTENSION_MAP[ext]

        # Fallback: try to parse as Python
        try:
            ast.parse(self.source_code)
            return "python"
        except SyntaxError:
            pass

        return "unknown"

    def analyze(self) -> NativeAnalysisResult:
        """Analyze source code and extract function contexts.

        Returns:
            NativeAnalysisResult with extracted functions
        """
        if self.language == "python":
            return self._analyze_python()
        elif self.language in self.FUNCTION_NODE_TYPES:
            # Use generic tree-sitter analyzer for all supported languages
            return self._analyze_tree_sitter()
        else:
            return NativeAnalysisResult(
                success=False,
                language=self.language,
                errors=[f"Unsupported language: {self.language}"],
            )

    def extract_all_function_contexts(self) -> List[FunctionContext]:
        """Extract contexts for ALL functions.

        This is the main entry point for fallback analysis.

        Returns:
            List of FunctionContext objects
        """
        result = self.analyze()
        return result.functions

    # =========================================================================
    # Python Analysis - Pure AST extraction
    # =========================================================================

    def _analyze_python(self) -> NativeAnalysisResult:
        """Analyze Python source code using built-in ast module."""
        functions = []
        errors = []
        partial = False

        try:
            tree = ast.parse(self.source_code, filename=str(self.file_path))
            module_imports = self._py_extract_imports(tree)

            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    try:
                        ctx = self._py_extract_function(node, module_imports)
                        functions.append(ctx)
                    except Exception as e:
                        errors.append(f"Failed to extract {node.name}: {e}")
                        partial = True

            return NativeAnalysisResult(
                success=True,
                language="python",
                functions=functions,
                errors=errors,
                partial=partial,
            )

        except SyntaxError as e:
            return NativeAnalysisResult(
                success=False,
                language="python",
                errors=[f"Syntax error: {e}"],
            )

    def _py_extract_imports(self, tree: ast.AST) -> List[str]:
        """Extract all imports from Python AST."""
        imports = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    stmt = f"import {alias.name}"
                    if alias.asname:
                        stmt += f" as {alias.asname}"
                    imports.append(stmt)
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                for alias in node.names:
                    stmt = f"from {module} import {alias.name}"
                    if alias.asname:
                        stmt += f" as {alias.asname}"
                    imports.append(stmt)
        return imports

    def _py_extract_function(
        self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef], module_imports: List[str]
    ) -> FunctionContext:
        """Extract FunctionContext from Python function AST node with full dataflow analysis.
        
        Uses the existing ForwardDataflowAnalysis infrastructure for proper
        CFG-based taint tracking with shape-aware analysis.
        """
        name = node.name
        docstring = ast.get_docstring(node)
        line_number = node.lineno

        # Extract decorators from AST
        decorator_types = []
        decorator_params: Dict[str, Dict[str, Any]] = {}
        for dec in node.decorator_list:
            dec_name = self._py_get_node_name(dec)
            decorator_types.append(dec_name)
            if isinstance(dec, ast.Call):
                dec_params = self._py_extract_call_kwargs(dec)
                if dec_params:
                    decorator_params[dec_name] = dec_params

        # Extract parameters from AST
        parameters = []
        param_names = []
        for arg in node.args.args:
            param_info: Dict[str, Any] = {"name": arg.arg}
            if arg.annotation:
                param_info["type"] = self._py_unparse_safe(arg.annotation)
            parameters.append(param_info)
            param_names.append(arg.arg)

        # Extract return type from AST
        return_type = self._py_unparse_safe(node.returns) if node.returns else None
        
        # Use existing ForwardDataflowAnalysis for proper CFG-based taint tracking
        parameter_flows = self._py_analyze_dataflow_full(node, param_names)
        
        # Detect security operations via dataflow
        security_ops = self._py_detect_security_ops(node)

        # Extract ALL function calls from AST
        function_calls = []
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                function_calls.append({
                    "name": self._py_get_node_name(child.func),
                    "args": [self._py_unparse_safe(a) for a in child.args],
                    "kwargs": {kw.arg: self._py_unparse_safe(kw.value) for kw in child.keywords if kw.arg},
                    "line": getattr(child, "lineno", 0),
                })

        # Extract ALL assignments from AST
        assignments = []
        for child in ast.walk(node):
            if isinstance(child, ast.Assign):
                for target in child.targets:
                    assignments.append({
                        "target": self._py_unparse_safe(target),
                        "value": self._py_unparse_safe(child.value),
                        "line": getattr(child, "lineno", 0),
                    })
            elif isinstance(child, ast.AnnAssign):
                assignments.append({
                    "target": self._py_unparse_safe(child.target),
                    "annotation": self._py_unparse_safe(child.annotation),
                    "value": self._py_unparse_safe(child.value) if child.value else None,
                    "line": getattr(child, "lineno", 0),
                })
            elif isinstance(child, ast.AugAssign):
                assignments.append({
                    "target": self._py_unparse_safe(child.target),
                    "op": child.op.__class__.__name__,
                    "value": self._py_unparse_safe(child.value),
                    "line": getattr(child, "lineno", 0),
                })

        # Extract control flow from AST
        control_flow = {
            "if_statements": [{"line": n.lineno, "test": self._py_unparse_safe(n.test)}
                             for n in ast.walk(node) if isinstance(n, ast.If)],
            "for_loops": [{"line": n.lineno, "target": self._py_unparse_safe(n.target),
                          "iter": self._py_unparse_safe(n.iter)}
                         for n in ast.walk(node) if isinstance(n, (ast.For, ast.AsyncFor))],
            "while_loops": [{"line": n.lineno, "test": self._py_unparse_safe(n.test)}
                           for n in ast.walk(node) if isinstance(n, ast.While)],
            "try_blocks": [{"line": n.lineno} for n in ast.walk(node) if isinstance(n, ast.Try)],
            "with_statements": [{"line": n.lineno, "items": [self._py_unparse_safe(i.context_expr) for i in n.items]}
                               for n in ast.walk(node) if isinstance(n, (ast.With, ast.AsyncWith))],
        }

        # Extract ALL constants from AST
        constants: Dict[str, Any] = {}
        for child in ast.walk(node):
            if isinstance(child, ast.Assign):
                for target in child.targets:
                    if isinstance(target, ast.Name) and isinstance(child.value, ast.Constant):
                        constants[target.id] = child.value.value

        # Extract variable dependencies from AST
        var_deps: Dict[str, List[str]] = {}
        for child in ast.walk(node):
            if isinstance(child, ast.Assign):
                for target in child.targets:
                    if isinstance(target, ast.Name):
                        deps = [n.id for n in ast.walk(child.value) if isinstance(n, ast.Name)]
                        var_deps[target.id] = deps

        # Extract ALL string literals from AST
        string_literals = []
        for child in ast.walk(node):
            if isinstance(child, ast.Constant) and isinstance(child.value, str):
                if child.value and len(child.value) <= 500:
                    string_literals.append(child.value)
        string_literals = list(set(string_literals))[:50]

        # Extract ALL return expressions from AST
        return_expressions = []
        for child in ast.walk(node):
            if isinstance(child, ast.Return) and child.value:
                return_expressions.append(self._py_unparse_safe(child.value))

        # Extract exception handlers from AST
        exception_handlers = []
        for child in ast.walk(node):
            if isinstance(child, ast.ExceptHandler):
                exception_handlers.append({
                    "line": child.lineno,
                    "type": self._py_unparse_safe(child.type) if child.type else "Exception",
                    "name": child.name,
                    "body_size": len(child.body),
                })

        # Extract global/nonlocal from AST
        global_writes = []
        for child in ast.walk(node):
            if isinstance(child, ast.Global):
                for name in child.names:
                    global_writes.append({"type": "global", "name": name, "line": child.lineno})
            elif isinstance(child, ast.Nonlocal):
                for name in child.names:
                    global_writes.append({"type": "nonlocal", "name": name, "line": child.lineno})

        # Extract attribute access from AST
        attribute_access = []
        for child in ast.walk(node):
            if isinstance(child, ast.Attribute):
                attribute_access.append({
                    "object": self._py_unparse_safe(child.value),
                    "attr": child.attr,
                    "line": getattr(child, "lineno", 0),
                })
        attribute_access = attribute_access[:50]

        # Extract subscript access from AST
        subscript_access = []
        for child in ast.walk(node):
            if isinstance(child, ast.Subscript):
                subscript_access.append({
                    "value": self._py_unparse_safe(child.value),
                    "slice": self._py_unparse_safe(child.slice),
                    "line": getattr(child, "lineno", 0),
                })

        # Calculate complexity from AST
        complexity = 1
        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.For, ast.While, ast.ExceptHandler, ast.With)):
                complexity += 1
            elif isinstance(child, ast.BoolOp):
                complexity += len(child.values) - 1

        # Build dataflow summary with taint info
        dataflow_summary = {
            "total_statements": len([n for n in ast.walk(node) if isinstance(n, ast.stmt)]),
            "total_expressions": len([n for n in ast.walk(node) if isinstance(n, ast.expr)]),
            "complexity": complexity,
            "subscript_access": subscript_access[:20],
            "param_flows": {p["parameter_name"]: {
                "reaches_calls": p.get("reaches_calls", []),
                "reaches_returns": p.get("reaches_returns", False),
                "reaches_external": p.get("reaches_external", False),
            } for p in parameter_flows},
        }

        # Build FunctionContext with dataflow analysis results
        return FunctionContext(
            name=name,
            decorator_types=decorator_types,
            decorator_params=decorator_params,
            docstring=docstring,
            parameters=parameters,
            return_type=return_type,
            line_number=line_number,
            imports=module_imports,
            function_calls=function_calls,
            assignments=assignments,
            control_flow=control_flow,
            parameter_flows=parameter_flows,  # Already list of dicts
            constants=constants,
            variable_dependencies=var_deps,
            has_file_operations=security_ops["has_file_operations"],
            has_network_operations=security_ops["has_network_operations"],
            has_subprocess_calls=security_ops["has_subprocess_calls"],
            has_eval_exec=security_ops["has_eval_exec"],
            has_dangerous_imports=any(d in " ".join(module_imports) for d in ["subprocess", "os", "pickle", "marshal"]),
            dataflow_summary=dataflow_summary,
            string_literals=string_literals,
            return_expressions=return_expressions,
            exception_handlers=exception_handlers,
            env_var_access=[],
            global_writes=global_writes,
            attribute_access=attribute_access,
        )

    def _py_get_node_name(self, node: ast.expr) -> str:
        """Get name from any AST expression node."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            parts = []
            current: ast.expr = node
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts))
        elif isinstance(node, ast.Call):
            return self._py_get_node_name(node.func)
        else:
            return self._py_unparse_safe(node)

    def _py_extract_call_kwargs(self, call: ast.Call) -> Dict[str, Any]:
        """Extract keyword arguments from a call node."""
        kwargs: Dict[str, Any] = {}
        for kw in call.keywords:
            if kw.arg:
                kwargs[kw.arg] = self._py_unparse_safe(kw.value)
        return kwargs

    def _py_unparse_safe(self, node: Optional[ast.AST]) -> str:
        """Safely unparse an AST node to string."""
        if node is None:
            return ""
        try:
            return ast.unparse(node)
        except Exception:
            return f"<{node.__class__.__name__}>"

    def _py_analyze_dataflow_full(
        self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef], param_names: List[str]
    ) -> List[Dict[str, Any]]:
        """Perform full dataflow analysis using existing ForwardDataflowAnalysis.
        
        This leverages the CFG-based taint tracking infrastructure from
        mcpscanner.core.static_analysis.dataflow and taint modules.
        """
        try:
            # Create a function-specific source for the parser
            func_source = ast.unparse(node)
            func_parser = PythonParser(func_source)
            func_parser.parse()
            
            # Use ForwardDataflowAnalysis for proper CFG-based analysis
            tracker = ForwardDataflowAnalysis(func_parser, param_names)
            flows = tracker.analyze_forward_flows()
            
            # Convert FlowPath objects to dicts for FunctionContext
            return [{
                "parameter_name": flow.parameter_name,
                "operations": flow.operations,
                "reaches_calls": flow.reaches_calls,
                "reaches_assignments": flow.reaches_assignments,
                "reaches_returns": flow.reaches_returns,
                "reaches_external": flow.reaches_external,
            } for flow in flows]
        except Exception as e:
            self.logger.debug(f"Full dataflow analysis failed, using simple analysis: {e}")
            # Fallback to simple analysis
            return self._py_analyze_dataflow_simple(node, param_names)

    def _py_analyze_dataflow_simple(
        self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef], param_names: List[str]
    ) -> List[Dict[str, Any]]:
        """Simple dataflow analysis fallback when full analysis fails."""
        # Reset taint environment
        self._taint_env = {}
        for pname in param_names:
            self._taint_env[pname] = TaintInfo(status=TaintStatus.TAINTED, sources={pname})
        
        flows = {name: {"parameter_name": name, "operations": [], "reaches_calls": [], 
                       "reaches_assignments": [], "reaches_returns": False, "reaches_external": False} 
                for name in param_names}
        
        external_patterns = {"open", "read", "write", "requests", "urllib", "subprocess", "os.system", "eval", "exec"}
        
        for child in ast.walk(node):
            if isinstance(child, ast.Assign):
                rhs_taint = self._py_eval_taint(child.value)
                for target in child.targets:
                    if isinstance(target, ast.Name):
                        self._taint_env[target.id] = rhs_taint
                        if rhs_taint.is_tainted():
                            for param in param_names:
                                if param in rhs_taint.sources:
                                    flows[param]["reaches_assignments"].append(target.id)
            
            elif isinstance(child, ast.Call):
                call_name = self._py_get_node_name(child.func)
                for arg in child.args:
                    arg_taint = self._py_eval_taint(arg)
                    if arg_taint.is_tainted():
                        for param in param_names:
                            if param in arg_taint.sources:
                                flows[param]["reaches_calls"].append(call_name)
                                if any(p in call_name for p in external_patterns):
                                    flows[param]["reaches_external"] = True
            
            elif isinstance(child, ast.Return) and child.value:
                ret_taint = self._py_eval_taint(child.value)
                if ret_taint.is_tainted():
                    for param in param_names:
                        if param in ret_taint.sources:
                            flows[param]["reaches_returns"] = True
        
        return list(flows.values())

    def _py_eval_taint(self, expr: ast.AST) -> TaintInfo:
        """Evaluate taint of a Python expression."""
        if isinstance(expr, ast.Name):
            return self._taint_env.get(expr.id, TaintInfo())
        elif isinstance(expr, ast.Attribute):
            return self._py_eval_taint(expr.value)
        elif isinstance(expr, ast.Subscript):
            return self._py_eval_taint(expr.value)
        elif isinstance(expr, ast.Call):
            result = TaintInfo()
            for arg in expr.args:
                result = result.merge(self._py_eval_taint(arg))
            for kw in expr.keywords:
                result = result.merge(self._py_eval_taint(kw.value))
            return result
        elif isinstance(expr, ast.BinOp):
            left = self._py_eval_taint(expr.left)
            right = self._py_eval_taint(expr.right)
            return left.merge(right)
        elif isinstance(expr, ast.JoinedStr):
            result = TaintInfo()
            for value in expr.values:
                if isinstance(value, ast.FormattedValue):
                    result = result.merge(self._py_eval_taint(value.value))
            return result
        elif isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
            result = TaintInfo()
            for elt in expr.elts:
                result = result.merge(self._py_eval_taint(elt))
            return result
        elif isinstance(expr, ast.Dict):
            result = TaintInfo()
            for v in expr.values:
                if v:
                    result = result.merge(self._py_eval_taint(v))
            return result
        return TaintInfo()

    def _py_detect_security_ops(self, node: ast.AST) -> Dict[str, bool]:
        """Detect security-relevant operations via dataflow analysis."""
        has_file = False
        has_network = False
        has_subprocess = False
        has_eval = False
        
        file_patterns = {"open", "read", "write", "close", "os.remove", "os.unlink", "shutil", "pathlib"}
        network_patterns = {"requests", "urllib", "http", "httpx", "aiohttp", "socket"}
        subprocess_patterns = {"subprocess", "os.system", "os.popen", "os.exec"}
        eval_patterns = {"eval", "exec", "compile", "__import__"}
        
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                call_name = self._py_get_node_name(child.func)
                
                if any(p in call_name for p in file_patterns):
                    has_file = True
                if any(p in call_name for p in network_patterns):
                    has_network = True
                if any(p in call_name for p in subprocess_patterns):
                    has_subprocess = True
                if call_name in eval_patterns:
                    has_eval = True
        
        return {
            "has_file_operations": has_file,
            "has_network_operations": has_network,
            "has_subprocess_calls": has_subprocess,
            "has_eval_exec": has_eval,
        }

    # =========================================================================
    # Generic Tree-sitter Analysis - Supports all non-Python languages
    # =========================================================================

    def _analyze_tree_sitter(self) -> NativeAnalysisResult:
        """Analyze source code using tree-sitter AST (generic for all languages)."""
        # Get the language module
        lang_mod = _get_language_module(self.language)
        if lang_mod is None:
            return NativeAnalysisResult(
                success=False,
                language=self.language,
                errors=[f"tree-sitter-{self.language} not available. Install: pip install tree-sitter-{self.language.replace('_', '-')}"],
            )

        functions = []
        errors = []

        try:
            # Get the language object
            if self.language == "typescript":
                lang = Language(lang_mod.language_typescript())
            elif self.language == "php":
                lang = Language(lang_mod.language_php())
            else:
                lang = Language(lang_mod.language())

            parser = Parser(lang)
            tree = parser.parse(self.source_bytes)

            # Extract imports from AST
            imports = self._ts_extract_imports(tree.root_node)

            # Extract all functions from AST
            self._ts_extract_functions(tree.root_node, imports, functions)

            return NativeAnalysisResult(
                success=True,
                language=self.language,
                functions=functions,
                errors=errors,
            )

        except Exception as e:
            return NativeAnalysisResult(
                success=False,
                language=self.language,
                errors=[f"Parse error: {e}"],
            )

    def _ts_extract_imports(self, root: "Node") -> List[str]:
        """Extract all imports from tree-sitter AST."""
        imports = []

        def visit(node: "Node"):
            # ES6 imports
            if node.type == "import_statement":
                imports.append(self._ts_get_node_text(node))
            # CommonJS require
            elif node.type == "call_expression":
                func = node.child_by_field_name("function")
                if func and self._ts_get_node_text(func) == "require":
                    imports.append(self._ts_get_node_text(node))
            for child in node.children:
                visit(child)

        visit(root)
        return imports

    def _ts_extract_functions(
        self, node: "Node", imports: List[str], functions: List[FunctionContext], class_name: str = ""
    ):
        """Recursively extract all functions from tree-sitter AST."""
        # Get function types for this language
        func_types = self.FUNCTION_NODE_TYPES.get(self.language, set())
        class_types = self.CLASS_NODE_TYPES.get(self.language, set())

        if node.type in func_types:
            try:
                ctx = self._ts_extract_function_context(node, imports, class_name)
                if ctx:
                    functions.append(ctx)
            except Exception as e:
                self.logger.warning(f"Failed to extract function: {e}")

        # Track class context
        current_class = class_name
        if node.type in class_types:
            name_node = node.child_by_field_name("name")
            if name_node:
                current_class = self._ts_get_node_text(name_node)

        # Recurse
        for child in node.children:
            self._ts_extract_functions(child, imports, functions, current_class)

    def _ts_extract_function_context(
        self, node: "Node", imports: List[str], class_name: str
    ) -> Optional[FunctionContext]:
        """Extract FunctionContext from tree-sitter function node with dataflow."""
        # Reset taint environment for this function
        self._taint_env = {}
        
        # Get function name
        name = self._ts_get_function_name(node)
        if class_name:
            name = f"{class_name}.{name}"

        # Get line number
        line_number = node.start_point[0] + 1

        # Extract parameters from AST and initialize taint tracking
        parameters = self._ts_extract_parameters(node)
        param_names = [p.get("name", "") for p in parameters if p.get("name")]
        for pname in param_names:
            self._taint_env[pname] = TaintInfo(status=TaintStatus.TAINTED, sources={pname})

        # Extract return type from AST (TypeScript)
        return_type = self._ts_extract_return_type(node)

        # Extract docstring/JSDoc from AST
        docstring = self._ts_extract_docstring(node)

        # Extract decorators from AST (TypeScript)
        decorator_types = self._ts_extract_decorators(node)

        # Extract ALL function calls from AST
        function_calls = self._ts_extract_calls(node)

        # Extract ALL assignments from AST
        assignments = self._ts_extract_assignments(node)

        # Extract control flow from AST
        control_flow = self._ts_extract_control_flow(node)

        # Extract ALL string literals from AST
        string_literals = self._ts_extract_strings(node)

        # Extract return expressions from AST
        return_expressions = self._ts_extract_returns(node)

        # Extract exception handlers from AST
        exception_handlers = self._ts_extract_catch_clauses(node)

        # Extract variable declarations from AST
        constants = self._ts_extract_constants(node)

        # Calculate complexity from AST
        complexity = self._ts_calculate_complexity(node)
        
        # Perform full CFG-based dataflow analysis
        parameter_flows = self._ts_analyze_dataflow_full(node, param_names)
        
        # Detect security operations
        security_ops = self._ts_detect_security_ops(node)
        
        # Extract raw context for LLM to parse tool descriptions
        raw_context = self._ts_extract_raw_context(node)
        
        # Build dataflow summary with raw context for LLM
        dataflow_summary = {
            "complexity": complexity,
            "param_flows": {p["parameter_name"]: {
                "reaches_calls": p.get("reaches_calls", []),
                "reaches_returns": p.get("reaches_returns", False),
                "reaches_external": p.get("reaches_external", False),
            } for p in parameter_flows},
            # Include raw context so LLM can parse tool descriptions
            "raw_decorator_context": raw_context,
        }

        return FunctionContext(
            name=name,
            decorator_types=decorator_types,
            decorator_params={},  # Empty - LLM will parse from raw_decorator_context
            docstring=docstring,
            parameters=parameters,
            return_type=return_type,
            line_number=line_number,
            imports=imports,
            function_calls=function_calls,
            assignments=assignments,
            control_flow=control_flow,
            parameter_flows=parameter_flows,  # Already list of dicts
            constants=constants,
            variable_dependencies={},
            has_file_operations=security_ops["has_file_operations"],
            has_network_operations=security_ops["has_network_operations"],
            has_subprocess_calls=security_ops["has_subprocess_calls"],
            has_eval_exec=security_ops["has_eval_exec"],
            has_dangerous_imports=False,
            dataflow_summary=dataflow_summary,
            string_literals=string_literals,
            return_expressions=return_expressions,
            exception_handlers=exception_handlers,
            env_var_access=[],
            global_writes=[],
            attribute_access=[],
        )

    def _ts_get_node_text(self, node: "Node") -> str:
        """Get text content of a tree-sitter node."""
        return self.source_bytes[node.start_byte:node.end_byte].decode("utf-8")

    def _ts_get_function_name(self, node: "Node") -> str:
        """Extract function name from tree-sitter node."""
        # Try name field
        name_node = node.child_by_field_name("name")
        if name_node:
            return self._ts_get_node_text(name_node)

        # For arrow functions assigned to variables, look at parent
        if node.type == "arrow_function" and node.parent:
            if node.parent.type == "variable_declarator":
                name_node = node.parent.child_by_field_name("name")
                if name_node:
                    return self._ts_get_node_text(name_node)

        return "<anonymous>"

    def _ts_extract_parameters(self, node: "Node") -> List[Dict[str, Any]]:
        """Extract parameters from tree-sitter function node."""
        params = []
        params_node = node.child_by_field_name("parameters")
        if not params_node:
            # Try various parameter list names
            for child in node.children:
                if child.type in ("formal_parameters", "parameters", "parameter_list"):
                    params_node = child
                    break

        if params_node:
            for child in params_node.children:
                param_info: Dict[str, Any] = {}
                
                # Handle different parameter node types across languages
                if child.type == "identifier":
                    # Simple identifier (JS/TS)
                    param_info["name"] = self._ts_get_node_text(child)
                
                elif child.type in ("required_parameter", "optional_parameter", "rest_parameter"):
                    # TypeScript parameters
                    name_node = child.child_by_field_name("pattern") or child.child_by_field_name("name")
                    if name_node:
                        param_info["name"] = self._ts_get_node_text(name_node)
                    type_node = child.child_by_field_name("type")
                    if type_node:
                        param_info["type"] = self._ts_get_node_text(type_node)
                
                elif child.type == "parameter_declaration":
                    # Go parameters
                    for subchild in child.children:
                        if subchild.type == "identifier":
                            param_info["name"] = self._ts_get_node_text(subchild)
                            break
                    # Get type (last non-identifier child)
                    for subchild in reversed(child.children):
                        if subchild.type not in ("identifier", ","):
                            param_info["type"] = self._ts_get_node_text(subchild)
                            break
                
                elif child.type == "formal_parameter":
                    # Java/Kotlin parameters
                    name_node = child.child_by_field_name("name")
                    type_node = child.child_by_field_name("type")
                    if name_node:
                        param_info["name"] = self._ts_get_node_text(name_node)
                    if type_node:
                        param_info["type"] = self._ts_get_node_text(type_node)
                
                elif child.type == "simple_parameter":
                    # Ruby parameters
                    param_info["name"] = self._ts_get_node_text(child)
                
                elif child.type == "parameter":
                    # Rust/PHP/Swift parameters
                    name_node = child.child_by_field_name("pattern") or child.child_by_field_name("name")
                    if name_node:
                        param_info["name"] = self._ts_get_node_text(name_node)
                    type_node = child.child_by_field_name("type")
                    if type_node:
                        param_info["type"] = self._ts_get_node_text(type_node)
                
                if param_info.get("name"):
                    params.append(param_info)
        
        return params

    def _ts_extract_return_type(self, node: "Node") -> Optional[str]:
        """Extract return type annotation from tree-sitter node."""
        return_type = node.child_by_field_name("return_type")
        if return_type:
            return self._ts_get_node_text(return_type)
        return None

    def _ts_extract_docstring(self, node: "Node") -> Optional[str]:
        """Extract JSDoc/doc comment from tree-sitter node.
        
        Captures comments that may contain tool descriptions for LLM analysis.
        """
        # Look for comment before function (JSDoc, block comment, etc.)
        if node.prev_sibling:
            sib = node.prev_sibling
            if sib.type in ("comment", "block_comment", "line_comment"):
                text = self._ts_get_node_text(sib)
                return text
        
        # Look for doc comment inside function (Go, Rust style)
        for child in node.children:
            if child.type in ("comment", "block_comment"):
                text = self._ts_get_node_text(child)
                return text
        
        return None

    def _ts_extract_decorators(self, node: "Node") -> List[str]:
        """Extract decorators/attributes from tree-sitter node.
        
        Captures full decorator text including arguments so LLM can parse
        tool descriptions like @tool(description="...") or #[tool(desc = "...")]
        """
        decorators = []
        
        # Check preceding siblings for decorators (TypeScript/Python style)
        sib = node.prev_sibling
        while sib:
            if sib.type in ("decorator", "attribute", "annotation"):
                decorators.append(self._ts_get_node_text(sib))
            elif sib.type == "comment":
                # Stop at comments (they're handled separately)
                break
            sib = sib.prev_sibling
        
        # Check children for decorators (some grammars nest them)
        for child in node.children:
            if child.type in ("decorator", "attribute", "annotation", "decorator_list"):
                if child.type == "decorator_list":
                    for dec in child.children:
                        decorators.append(self._ts_get_node_text(dec))
                else:
                    decorators.append(self._ts_get_node_text(child))
        
        # Reverse to get original order
        decorators.reverse()
        return decorators
    
    def _ts_extract_raw_context(self, node: "Node") -> str:
        """Extract raw context around function for LLM to parse tool descriptions.
        
        Captures surrounding code context so LLM can figure out tool descriptions
        from any pattern (decorators, call arguments, comments, etc.)
        """
        lines = self.source_bytes.decode("utf-8").split("\n")
        
        # For arrow functions/callbacks, find the parent call expression
        # This captures patterns like: server.registerTool('name', { description: '...' }, async () => {})
        parent_start = node.start_point[0]
        parent = node.parent
        while parent:
            if parent.type in ("call_expression", "expression_statement", "variable_declaration"):
                parent_start = parent.start_point[0]
                break
            parent = parent.parent
        
        # Get context: from parent start (or 10 lines before) to function start + 1
        start_line = max(0, min(parent_start, node.start_point[0] - 10))
        end_line = min(len(lines), node.start_point[0] + 2)
        
        context_lines = []
        for i in range(start_line, end_line):
            if i < len(lines):
                context_lines.append(lines[i])
        
        return "\n".join(context_lines)

    def _ts_extract_calls(self, node: "Node") -> List[Dict[str, Any]]:
        """Extract ALL function calls from tree-sitter AST."""
        calls = []

        def visit(n: "Node"):
            if n.type == "call_expression":
                func = n.child_by_field_name("function")
                args = n.child_by_field_name("arguments")
                calls.append({
                    "name": self._ts_get_node_text(func) if func else "<unknown>",
                    "args": self._ts_get_node_text(args) if args else "()",
                    "line": n.start_point[0] + 1,
                })
            for child in n.children:
                visit(child)

        visit(node)
        return calls

    def _ts_extract_assignments(self, node: "Node") -> List[Dict[str, Any]]:
        """Extract ALL assignments from tree-sitter AST."""
        assignments = []

        def visit(n: "Node"):
            if n.type == "assignment_expression":
                left = n.child_by_field_name("left")
                right = n.child_by_field_name("right")
                assignments.append({
                    "target": self._ts_get_node_text(left) if left else "",
                    "value": self._ts_get_node_text(right) if right else "",
                    "line": n.start_point[0] + 1,
                })
            elif n.type == "variable_declarator":
                name = n.child_by_field_name("name")
                value = n.child_by_field_name("value")
                if name:
                    assignments.append({
                        "target": self._ts_get_node_text(name),
                        "value": self._ts_get_node_text(value) if value else None,
                        "line": n.start_point[0] + 1,
                    })
            for child in n.children:
                visit(child)

        visit(node)
        return assignments

    def _ts_extract_control_flow(self, node: "Node") -> Dict[str, Any]:
        """Extract control flow from tree-sitter AST."""
        control_flow: Dict[str, List[Dict[str, Any]]] = {
            "if_statements": [],
            "for_loops": [],
            "while_loops": [],
            "try_blocks": [],
            "switch_statements": [],
        }

        def visit(n: "Node"):
            if n.type == "if_statement":
                cond = n.child_by_field_name("condition")
                control_flow["if_statements"].append({
                    "line": n.start_point[0] + 1,
                    "condition": self._ts_get_node_text(cond) if cond else "",
                })
            elif n.type in ("for_statement", "for_in_statement"):
                control_flow["for_loops"].append({
                    "line": n.start_point[0] + 1,
                    "header": self._ts_get_node_text(n)[:100],
                })
            elif n.type == "while_statement":
                cond = n.child_by_field_name("condition")
                control_flow["while_loops"].append({
                    "line": n.start_point[0] + 1,
                    "condition": self._ts_get_node_text(cond) if cond else "",
                })
            elif n.type == "try_statement":
                control_flow["try_blocks"].append({"line": n.start_point[0] + 1})
            elif n.type == "switch_statement":
                control_flow["switch_statements"].append({"line": n.start_point[0] + 1})
            for child in n.children:
                visit(child)

        visit(node)
        return control_flow

    def _ts_extract_strings(self, node: "Node") -> List[str]:
        """Extract ALL string literals from tree-sitter AST."""
        strings = []

        def visit(n: "Node"):
            if n.type in ("string", "template_string"):
                text = self._ts_get_node_text(n)
                if text and len(text) <= 500:
                    strings.append(text)
            for child in n.children:
                visit(child)

        visit(node)
        return list(set(strings))[:50]

    def _ts_extract_returns(self, node: "Node") -> List[str]:
        """Extract return expressions from tree-sitter AST."""
        returns = []

        def visit(n: "Node"):
            if n.type == "return_statement":
                # Get the expression after 'return'
                for child in n.children:
                    if child.type not in ("return", ";"):
                        returns.append(self._ts_get_node_text(child))
                        break
            for child in n.children:
                visit(child)

        visit(node)
        return returns

    def _ts_extract_catch_clauses(self, node: "Node") -> List[Dict[str, Any]]:
        """Extract catch clauses from tree-sitter AST."""
        handlers = []

        def visit(n: "Node"):
            if n.type == "catch_clause":
                param = n.child_by_field_name("parameter")
                handlers.append({
                    "line": n.start_point[0] + 1,
                    "parameter": self._ts_get_node_text(param) if param else None,
                })
            for child in n.children:
                visit(child)

        visit(node)
        return handlers

    def _ts_extract_constants(self, node: "Node") -> Dict[str, Any]:
        """Extract constants from tree-sitter AST."""
        constants: Dict[str, Any] = {}

        def visit(n: "Node"):
            if n.type == "variable_declarator":
                name = n.child_by_field_name("name")
                value = n.child_by_field_name("value")
                if name and value and value.type in ("number", "string", "true", "false", "null"):
                    constants[self._ts_get_node_text(name)] = self._ts_get_node_text(value)
            for child in n.children:
                visit(child)

        visit(node)
        return constants

    def _ts_calculate_complexity(self, node: "Node") -> int:
        """Calculate cyclomatic complexity from tree-sitter AST."""
        complexity = 1
        branch_types = {
            "if_statement", "for_statement", "for_in_statement", "while_statement",
            "do_statement", "switch_case", "catch_clause", "ternary_expression",
            "binary_expression",  # for && and ||
        }

        def visit(n: "Node"):
            nonlocal complexity
            if n.type in branch_types:
                if n.type == "binary_expression":
                    op = n.child_by_field_name("operator")
                    if op and self._ts_get_node_text(op) in ("&&", "||"):
                        complexity += 1
                else:
                    complexity += 1
            for child in n.children:
                visit(child)

        visit(node)
        return complexity

    def _ts_analyze_dataflow_full(self, node: "Node", param_names: List[str]) -> List[Dict[str, Any]]:
        """Perform full CFG-based dataflow analysis using TreeSitterDataflowAnalysis.
        
        This leverages the CFG builder and dataflow infrastructure to provide
        the same level of analysis as Python's ForwardDataflowAnalysis.
        """
        try:
            # Use full CFG-based dataflow analysis
            analyzer = TreeSitterDataflowAnalysis(
                language=self.language,
                function_node=node,
                param_names=param_names,
                source_bytes=self.source_bytes,
            )
            flows = analyzer.analyze()
            
            # Convert TSFlowPath objects to dicts
            return [flow.to_dict() for flow in flows]
        except Exception as e:
            self.logger.debug(f"Full tree-sitter dataflow analysis failed, using simple: {e}")
            # Fallback to simple analysis
            return self._ts_analyze_dataflow_simple(node, param_names)

    def _ts_analyze_dataflow_simple(self, node: "Node", param_names: List[str]) -> List[Dict[str, Any]]:
        """Simple fallback dataflow analysis when full analysis fails."""
        # Reset taint environment
        self._taint_env = {}
        for pname in param_names:
            self._taint_env[pname] = TaintInfo(status=TaintStatus.TAINTED, sources={pname})
        
        flows = {name: {"parameter_name": name, "operations": [], "reaches_calls": [],
                       "reaches_assignments": [], "reaches_returns": False, "reaches_external": False}
                for name in param_names}
        
        external_patterns = {"open", "read", "write", "fetch", "exec", "spawn", "system", "eval"}
        
        def visit(n: "Node"):
            if n.type in ("assignment_expression", "variable_declarator", "short_var_declaration"):
                target = n.child_by_field_name("left") or n.child_by_field_name("name")
                value = n.child_by_field_name("right") or n.child_by_field_name("value")
                
                if target and value:
                    target_name = self._ts_get_node_text(target)
                    taint = self._ts_eval_taint(value, param_names)
                    if target_name:
                        self._taint_env[target_name] = taint
                    if taint.is_tainted():
                        for param in param_names:
                            if param in taint.sources:
                                flows[param]["reaches_assignments"].append(target_name)
            
            elif n.type in ("call_expression", "new_expression", "method_invocation"):
                func = n.child_by_field_name("function") or n.child_by_field_name("name")
                args = n.child_by_field_name("arguments")
                if func and args:
                    call_name = self._ts_get_node_text(func)
                    args_taint = self._ts_eval_taint(args, param_names)
                    if args_taint.is_tainted():
                        for param in param_names:
                            if param in args_taint.sources:
                                flows[param]["reaches_calls"].append(call_name)
                                if any(p in call_name for p in external_patterns):
                                    flows[param]["reaches_external"] = True
            
            elif n.type == "return_statement":
                for child in n.children:
                    if child.type not in ("return", ";", "keyword"):
                        ret_taint = self._ts_eval_taint(child, param_names)
                        if ret_taint.is_tainted():
                            for param in param_names:
                                if param in ret_taint.sources:
                                    flows[param]["reaches_returns"] = True
                        break
            
            for child in n.children:
                visit(child)
        
        visit(node)
        return list(flows.values())

    def _ts_eval_taint(self, node: "Node", param_names: List[str]) -> TaintInfo:
        """Evaluate taint of tree-sitter expression via AST traversal."""
        result = TaintInfo()
        
        def visit(n: "Node") -> TaintInfo:
            """Recursively evaluate taint of AST node."""
            node_taint = TaintInfo()
            
            # Check if this is an identifier
            if n.type == "identifier":
                var_name = self._ts_get_node_text(n)
                # Direct parameter reference
                if var_name in param_names:
                    node_taint = TaintInfo(status=TaintStatus.TAINTED, sources={var_name})
                # Variable in taint environment
                elif var_name in self._taint_env:
                    node_taint = self._taint_env[var_name]
            
            # For compound expressions, merge taint from children
            for child in n.children:
                child_taint = visit(child)
                node_taint = node_taint.merge(child_taint)
            
            return node_taint
        
        return visit(node)

    def _ts_detect_security_ops(self, node: "Node") -> Dict[str, bool]:
        """Detect security-relevant operations via AST traversal."""
        from .taint.patterns import get_all_sinks_for_language
        
        has_file = False
        has_network = False
        has_subprocess = False
        has_eval = False
        has_sql = False
        has_deserialization = False
        
        # Get comprehensive sink patterns for this language
        sinks = get_all_sinks_for_language(self.language)
        command_sinks = sinks.get("command", set())
        sql_sinks = sinks.get("sql", set())
        eval_sinks = sinks.get("eval", set())
        file_sinks = sinks.get("file", set())
        network_sinks = sinks.get("network", set())
        deser_sinks = sinks.get("deserialization", set())
        
        def matches_sink(func_text: str, sink_set: set) -> bool:
            """Check if function text matches any sink pattern."""
            # Normalize the function text
            normalized = func_text.replace("::", ".").replace("->", ".")
            parts = normalized.split(".")
            func_name = parts[-1] if parts else normalized
            
            for sink in sink_set:
                # Normalize sink pattern too
                sink_normalized = sink.replace("::", ".").replace("->", ".")
                sink_parts = sink_normalized.split(".")
                sink_func = sink_parts[-1] if sink_parts else sink_normalized
                
                # Exact match (normalized)
                if normalized == sink_normalized:
                    return True
                # Function name match
                if func_name == sink_func:
                    return True
                # Partial match (sink pattern in function text)
                if sink_normalized in normalized:
                    return True
            return False
        
        def visit(n: "Node"):
            nonlocal has_file, has_network, has_subprocess, has_eval, has_sql, has_deserialization
            
            # Check call expressions (expanded for all languages)
            if n.type in ("call_expression", "method_invocation", "function_call_expression",
                         "member_call_expression", "scoped_call_expression", "call", "method_call",
                         "invocation_expression", "object_creation_expression", "new_expression"):
                func = n.child_by_field_name("function") or n.child_by_field_name("name") or n.child_by_field_name("method")
                if func:
                    func_text = self._ts_get_node_text(func)
                else:
                    func_text = self._ts_get_node_text(n)
                
                # Check against sink patterns
                if matches_sink(func_text, command_sinks):
                    has_subprocess = True
                if matches_sink(func_text, sql_sinks):
                    has_sql = True
                if matches_sink(func_text, eval_sinks):
                    has_eval = True
                if matches_sink(func_text, file_sinks):
                    has_file = True
                if matches_sink(func_text, network_sinks):
                    has_network = True
                if matches_sink(func_text, deser_sinks):
                    has_deserialization = True
            
            for child in n.children:
                visit(child)
        
        visit(node)
        
        return {
            "has_file_operations": has_file,
            "has_network_operations": has_network,
            "has_subprocess_calls": has_subprocess,
            "has_eval_exec": has_eval,
            "has_sql_operations": has_sql,
            "has_deserialization": has_deserialization,
        }
