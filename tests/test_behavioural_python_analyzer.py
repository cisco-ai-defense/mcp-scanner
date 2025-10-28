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

"""Tests for behavioural.analyzers.python_analyzer module."""

import pytest
import ast
from pathlib import Path
from mcpscanner.behavioural.analyzers.python_analyzer import PythonAnalyzer


class TestPythonAnalyzerInit:
    def test_init_with_valid_code(self):
        code = "x = 1"
        analyzer = PythonAnalyzer(Path("test.py"), code)
        assert analyzer.file_path == Path("test.py")
        assert analyzer.source_code == code

    def test_init_with_empty_code(self):
        analyzer = PythonAnalyzer(Path("test.py"), "")
        assert analyzer.source_code == ""


class TestPythonAnalyzerParse:
    def test_parse_valid_code(self):
        code = "x = 1\ny = 2"
        analyzer = PythonAnalyzer(Path("test.py"), code)
        tree = analyzer.parse()
        assert isinstance(tree, ast.Module)

    def test_parse_invalid_code(self):
        code = "def broken("
        analyzer = PythonAnalyzer(Path("test.py"), code)
        with pytest.raises(SyntaxError):
            analyzer.parse()

    def test_parse_function_definition(self):
        code = "def foo(x): return x"
        analyzer = PythonAnalyzer(Path("test.py"), code)
        tree = analyzer.parse()
        assert any(isinstance(node, ast.FunctionDef) for node in ast.walk(tree))

    def test_parse_class_definition(self):
        code = "class MyClass: pass"
        analyzer = PythonAnalyzer(Path("test.py"), code)
        tree = analyzer.parse()
        assert any(isinstance(node, ast.ClassDef) for node in ast.walk(tree))


class TestPythonAnalyzerGetNodeRange:
    def test_get_node_range(self):
        code = "x = 1"
        analyzer = PythonAnalyzer(Path("test.py"), code)
        tree = analyzer.parse()
        assign_node = tree.body[0]
        range_obj = analyzer.get_node_range(assign_node)
        assert range_obj is not None
        assert range_obj.start.line >= 1
        assert range_obj.end.line >= 1


class TestPythonAnalyzerGetNodeText:
    def test_get_node_text(self):
        code = "x = 1 + 2"
        analyzer = PythonAnalyzer(Path("test.py"), code)
        tree = analyzer.parse()
        assign_node = tree.body[0]
        text = analyzer.get_node_text(assign_node)
        assert "x" in text or "1" in text
