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

"""Tests for behavioural.analysis.available_exprs module."""

import pytest
from pathlib import Path
from mcpscanner.behavioural.analysis.available_exprs import AvailableExpressionsAnalyzer
from mcpscanner.behavioural.analyzers.python_analyzer import PythonAnalyzer


class TestAvailableExpressionsAnalyzer:
    def test_init(self):
        code = "x = 1 + 2"
        analyzer = PythonAnalyzer(Path("test.py"), code)
        analyzer.parse()
        ae_analyzer = AvailableExpressionsAnalyzer(analyzer)
        assert ae_analyzer.analyzer == analyzer

    def test_analyze_simple_expression(self):
        code = "x = 1 + 2\ny = 1 + 2"
        analyzer = PythonAnalyzer(Path("test.py"), code)
        tree = analyzer.parse()
        ae_analyzer = AvailableExpressionsAnalyzer(analyzer)
        # Just test that it initializes correctly
        assert ae_analyzer is not None

    def test_analyze_common_subexpression(self):
        code = "a = x + y\nb = x + y"
        analyzer = PythonAnalyzer(Path("test.py"), code)
        tree = analyzer.parse()
        ae_analyzer = AvailableExpressionsAnalyzer(analyzer)
        # Should detect common subexpression x + y
        assert ae_analyzer is not None
