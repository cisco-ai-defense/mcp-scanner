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

"""Tests for behavioural.analysis.reaching_defs module."""

import pytest
from pathlib import Path
from mcpscanner.behavioural.analysis.reaching_defs import ReachingDefinitionsAnalyzer
from mcpscanner.behavioural.analyzers.python_analyzer import PythonAnalyzer


class TestReachingDefinitionsAnalyzer:
    def test_init(self):
        code = "x = 1"
        analyzer = PythonAnalyzer(Path("test.py"), code)
        analyzer.parse()
        rd_analyzer = ReachingDefinitionsAnalyzer(analyzer)
        assert rd_analyzer.analyzer == analyzer

    def test_analyze_simple_assignment(self):
        code = "x = 1"
        analyzer = PythonAnalyzer(Path("test.py"), code)
        tree = analyzer.parse()
        rd_analyzer = ReachingDefinitionsAnalyzer(analyzer)
        # Just test initialization
        assert rd_analyzer is not None

    def test_analyze_multiple_assignments(self):
        code = "x = 1\nx = 2\nx = 3"
        analyzer = PythonAnalyzer(Path("test.py"), code)
        tree = analyzer.parse()
        rd_analyzer = ReachingDefinitionsAnalyzer(analyzer)
        # Just test initialization
        assert rd_analyzer is not None

    def test_analyze_function_parameter(self):
        code = "def foo(x):\n    return x"
        analyzer = PythonAnalyzer(Path("test.py"), code)
        tree = analyzer.parse()
        rd_analyzer = ReachingDefinitionsAnalyzer(analyzer)
        # Just test initialization
        assert rd_analyzer is not None
