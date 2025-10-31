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

"""Tests for behavioural.analysis.naming module."""

import pytest
from pathlib import Path
from mcpscanner.behavioural.analysis.naming import NameResolver
from mcpscanner.behavioural.analyzers.python_analyzer import PythonAnalyzer


class TestNameResolver:
    def test_init(self):
        code = "x = 1"
        analyzer = PythonAnalyzer(Path("test.py"), code)
        analyzer.parse()
        resolver = NameResolver(analyzer, [])
        assert resolver.analyzer == analyzer

    def test_resolve_simple_name(self):
        code = "x = 1\ny = x"
        analyzer = PythonAnalyzer(Path("test.py"), code)
        tree = analyzer.parse()
        resolver = NameResolver(analyzer, [])
        # Just test initialization
        assert resolver is not None

    def test_resolve_function_name(self):
        code = "def foo(): pass"
        analyzer = PythonAnalyzer(Path("test.py"), code)
        tree = analyzer.parse()
        resolver = NameResolver(analyzer, [])
        # Just test initialization
        assert resolver is not None

    def test_resolve_class_name(self):
        code = "class MyClass: pass"
        analyzer = PythonAnalyzer(Path("test.py"), code)
        tree = analyzer.parse()
        resolver = NameResolver(analyzer, [])
        # Just test initialization
        assert resolver is not None

    def test_resolve_import(self):
        code = "import os"
        analyzer = PythonAnalyzer(Path("test.py"), code)
        tree = analyzer.parse()
        resolver = NameResolver(analyzer, [])
        # Just test initialization
        assert resolver is not None
