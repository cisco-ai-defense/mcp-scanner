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

"""Tests for behavioural.analysis.constant_prop module."""

import pytest
from pathlib import Path
from mcpscanner.behavioural.analysis.constant_prop import ConstantPropagator
from mcpscanner.behavioural.analyzers.python_analyzer import PythonAnalyzer


class TestConstantPropagator:
    def test_init(self):
        code = "x = 1"
        analyzer = PythonAnalyzer(Path("test.py"), code)
        analyzer.parse()
        prop = ConstantPropagator(analyzer)
        assert prop.analyzer == analyzer

    def test_analyze_simple_constant(self):
        code = "x = 42"
        analyzer = PythonAnalyzer(Path("test.py"), code)
        analyzer.parse()
        prop = ConstantPropagator(analyzer)
        prop.analyze()
        assert "x" in prop.constants
        assert prop.constants["x"] == 42

    def test_analyze_string_constant(self):
        code = "name = 'test'"
        analyzer = PythonAnalyzer(Path("test.py"), code)
        analyzer.parse()
        prop = ConstantPropagator(analyzer)
        prop.analyze()
        assert "name" in prop.constants

    def test_analyze_multiple_constants(self):
        code = "x = 1\ny = 2\nz = 3"
        analyzer = PythonAnalyzer(Path("test.py"), code)
        analyzer.parse()
        prop = ConstantPropagator(analyzer)
        prop.analyze()
        assert len(prop.constants) >= 3

    def test_analyze_non_constant(self):
        code = "x = input()"
        analyzer = PythonAnalyzer(Path("test.py"), code)
        analyzer.parse()
        prop = ConstantPropagator(analyzer)
        prop.analyze()
        # x should not be in constants since it's not a constant value
        assert "x" not in prop.constants or prop.constants["x"] is None
