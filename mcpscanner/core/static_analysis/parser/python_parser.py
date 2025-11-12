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

"""Python source code parser using built-in AST module.

This parser provides Python-specific parsing functionality for the
static analysis engine, following SAST tool conventions.
"""

import ast
from pathlib import Path
from typing import Any

from .base import BaseParser
from ..types import Position, Range


class PythonParser(BaseParser):
    """Parser for Python code using the built-in ast module.
    
    Provides comprehensive Python AST parsing and traversal capabilities
    for static security analysis.
    """

    def __init__(self, file_path: Path, source_code: str) -> None:
        """Initialize Python parser.

        Args:
            file_path: Path to the Python source file
            source_code: Python source code content
        """
        super().__init__(file_path, source_code)

    def parse(self) -> ast.AST:
        """Parse Python source code into AST.

        Returns:
            Python AST

        Raises:
            SyntaxError: If source code has syntax errors
        """
        try:
            return ast.parse(self.source_code, filename=str(self.file_path))
        except SyntaxError as e:
            raise SyntaxError(f"Failed to parse {self.file_path}: {e}") from e

    def get_node_range(self, node: ast.AST) -> Range:
        """Get source range for an AST node.

        Args:
            node: Python AST node

        Returns:
            Source range
        """
        if not hasattr(node, "lineno"):
            return Range(
                start=Position(line=0, column=0, offset=0),
                end=Position(line=0, column=0, offset=0),
            )

        start_line = node.lineno
        start_col = node.col_offset if hasattr(node, "col_offset") else 0

        # Handle end position: use end_lineno/end_col_offset if available
        # The 'or' fallback handles cases where these attributes exist but are None
        # (can occur with certain AST node types or incomplete parsing)
        if hasattr(node, "end_lineno") and hasattr(node, "end_col_offset"):
            end_line = node.end_lineno or start_line
            end_col = node.end_col_offset or start_col
        else:
            end_line = start_line
            end_col = start_col + 1

        return Range(
            start=Position(line=start_line, column=start_col, offset=0),
            end=Position(line=end_line, column=end_col, offset=0),
        )

    def get_node_text(self, node: ast.AST) -> str:
        """Get source text for an AST node.

        Args:
            node: Python AST node

        Returns:
            Source code text
        """
        try:
            return ast.unparse(node)
        except Exception:
            range_obj = self.get_node_range(node)
            if range_obj.start.line == 0:
                return ""

            start_line = range_obj.start.line - 1
            end_line = range_obj.end.line - 1

            if start_line == end_line:
                line = self.lines[start_line]
                return line[range_obj.start.column : range_obj.end.column]
            else:
                lines = []
                for i in range(start_line, end_line + 1):
                    if i < len(self.lines):
                        lines.append(self.lines[i])
                return "\n".join(lines)

    def walk(self, node: ast.AST | None = None) -> list[ast.AST]:
        """Walk AST and return all nodes.

        Uses the built-in ast.walk() which is more efficient than recursive traversal.

        Args:
            node: Starting node (None for root)

        Returns:
            List of all AST nodes
        """
        if node is None:
            node = self.get_ast()

        return list(ast.walk(node))

    def get_function_calls(self, node: ast.AST | None = None) -> list[ast.Call]:
        """Get all function calls in the AST.

        Args:
            node: Starting node (None for root)

        Returns:
            List of Call nodes
        """
        if node is None:
            node = self.get_ast()

        calls: list[ast.Call] = []
        for n in self.walk(node):
            if isinstance(n, ast.Call):
                calls.append(n)

        return calls

    def get_assignments(self, node: ast.AST | None = None) -> list[ast.Assign | ast.AnnAssign | ast.AugAssign]:
        """Get all assignments in the AST.

        Includes regular assignments (=), annotated assignments (a: int = 1), and augmented assignments (+=, -=, etc.).
        Note: Does not include walrus operator (:=) which is ast.NamedExpr.

        Args:
            node: Starting node (None for root)

        Returns:
            List of assignment nodes
        """
        if node is None:
            node = self.get_ast()

        assignments: list[ast.Assign | ast.AnnAssign | ast.AugAssign] = []
        for n in self.walk(node):
            if isinstance(n, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                assignments.append(n)

        return assignments

    def get_function_defs(self, node: ast.AST | None = None) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
        """Get all function definitions in the AST.

        Includes both regular and async function definitions.

        Args:
            node: Starting node (None for root)

        Returns:
            List of FunctionDef and AsyncFunctionDef nodes
        """
        if node is None:
            node = self.get_ast()

        funcs: list[ast.FunctionDef | ast.AsyncFunctionDef] = []
        for n in self.walk(node):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                funcs.append(n)

        return funcs

    def get_imports(self, node: ast.AST | None = None) -> list[ast.Import | ast.ImportFrom]:
        """Get all import statements in the AST.

        Args:
            node: Starting node (None for root)

        Returns:
            List of import nodes
        """
        if node is None:
            node = self.get_ast()

        imports: list[ast.Import | ast.ImportFrom] = []
        for n in self.walk(node):
            if isinstance(n, (ast.Import, ast.ImportFrom)):
                imports.append(n)

        return imports

    def get_node_type(self, node: ast.AST) -> str:
        """Get the type name of an AST node.

        Args:
            node: AST node

        Returns:
            Type name as string
        """
        return node.__class__.__name__

    def is_call_to(self, node: ast.AST, func_name: str) -> bool:
        """Check if node is a call to a specific function.

        Args:
            node: AST node
            func_name: Function name to check

        Returns:
            True if node is a call to func_name
        """
        if not isinstance(node, ast.Call):
            return False

        if isinstance(node.func, ast.Name):
            return node.func.id == func_name

        if isinstance(node.func, ast.Attribute):
            return node.func.attr == func_name

        return False

    def get_call_name(self, node: ast.Call) -> str:
        """Get the name of a function call.

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
        else:
            try:
                return ast.unparse(node.func)
            except (AttributeError, TypeError, ValueError):
                return "<unknown_call>"

    def get_docstring(self, node: ast.AST) -> str | None:
        """Extract docstring from a function or class definition.

        Args:
            node: AST node (FunctionDef, AsyncFunctionDef, ClassDef, or Module)

        Returns:
            Docstring text if present, None otherwise
        """
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Module)):
            return None

        # Try ast.get_docstring() first (standard approach)
        try:
            docstring = ast.get_docstring(node)
            if docstring:
                return docstring
        except (AttributeError, TypeError):
            pass

        # Fallback: manual extraction for edge cases
        if not node.body:
            return None

        first_stmt = node.body[0]
        
        if isinstance(first_stmt, ast.Expr):
            value = first_stmt.value
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                return value.value
            elif hasattr(ast, 'Str') and isinstance(value, ast.Str):
                return value.s

        return None
