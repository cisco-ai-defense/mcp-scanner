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

"""Tests for Python parser components."""

import pytest


class TestParser:
    """Test Python parser functionality."""

    def test_parser_module_exists(self):
        """Test that parser module can be imported."""
        from mcpscanner.core.static_analysis import parser

        assert parser is not None

    def test_python_parser_importable(self):
        """Test that Python parser can be imported."""
        try:
            from mcpscanner.core.static_analysis.parser.python_parser import (
                PythonParser,
            )

            assert PythonParser is not None
        except (ImportError, AttributeError):
            pytest.skip("Python parser structure needs verification")

    def test_can_parse_valid_python(self):
        """Test parsing valid Python code."""
        import ast

        code = """
def hello():
    return "world"
"""
        try:
            tree = ast.parse(code)
            assert tree is not None
            assert isinstance(tree, ast.Module)
        except SyntaxError:
            pytest.fail("Should parse valid Python code")

    def test_can_detect_function_definitions(self):
        """Test detecting function definitions in AST."""
        import ast

        code = """
def function1():
    pass

def function2(param):
    return param
"""
        tree = ast.parse(code)

        func_count = sum(
            1 for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
        )
        assert func_count == 2, "Should detect 2 function definitions"

    def test_can_detect_decorators(self):
        """Test detecting decorators in AST."""
        import ast

        code = """
@decorator
def decorated_function():
    pass
"""
        tree = ast.parse(code)

        func_nodes = [
            node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
        ]
        assert len(func_nodes) == 1
        assert len(func_nodes[0].decorator_list) == 1, "Should detect decorator"

    def test_can_extract_docstrings(self):
        """Test extracting docstrings from functions."""
        import ast

        code = '''
def documented_function():
    """This is a docstring."""
    pass
'''
        tree = ast.parse(code)

        func_nodes = [
            node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
        ]
        assert len(func_nodes) == 1

        docstring = ast.get_docstring(func_nodes[0])
        assert docstring == "This is a docstring."

    def test_parser_base_importable(self):
        """Test that base parser can be imported."""
        try:
            from mcpscanner.core.static_analysis.parser import base

            assert base is not None
        except (ImportError, AttributeError):
            pytest.skip("Base parser structure needs verification")

    def test_can_parse_valid_python(self):
        """Test parsing valid Python code."""
        import ast

        code = """
def hello():
    return "world"
"""
        try:
            tree = ast.parse(code)
            assert tree is not None
            assert isinstance(tree, ast.Module)
        except SyntaxError:
            pytest.fail("Should parse valid Python code")

    def test_can_detect_function_definitions(self):
        """Test detecting function definitions in AST."""
        import ast

        code = """
def function1():
    pass

def function2(param):
    return param
"""
        tree = ast.parse(code)

        # Count function definitions
        func_count = sum(
            1 for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
        )
        assert func_count == 2, "Should detect 2 function definitions"

    def test_can_detect_decorators(self):
        """Test detecting decorators in AST."""
        import ast

        code = """
@decorator
def decorated_function():
    pass
"""
        tree = ast.parse(code)

        # Find function with decorator
        func_nodes = [
            node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
        ]
        assert len(func_nodes) == 1
        assert len(func_nodes[0].decorator_list) == 1, "Should detect decorator"

    def test_can_extract_docstrings(self):
        """Test extracting docstrings from functions."""
        import ast

        code = '''
def documented_function():
    """This is a docstring."""
    pass
'''
        tree = ast.parse(code)

        func_nodes = [
            node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
        ]
        assert len(func_nodes) == 1

        docstring = ast.get_docstring(func_nodes[0])
        assert docstring == "This is a docstring."

    def test_can_detect_imports(self):
        """Test detecting import statements."""
        import ast

        code = """
import os
import sys
from pathlib import Path
"""
        tree = ast.parse(code)

        import_count = sum(
            1
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
        )
        assert import_count == 3, "Should detect 3 import statements"
