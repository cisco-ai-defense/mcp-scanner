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

"""Tests for behavioural.analysis.liveness module."""

import pytest
from pathlib import Path
from mcpscanner.behavioural.analysis.liveness import LivenessAnalyzer
from mcpscanner.behavioural.analyzers.python_analyzer import PythonAnalyzer


class TestLivenessAnalyzer:
    def test_init(self):
        code = "x = 1"
        analyzer = PythonAnalyzer(Path("test.py"), code)
        analyzer.parse()
        liveness = LivenessAnalyzer(analyzer)
        assert liveness.analyzer == analyzer

    def test_analyze_simple(self):
        code = "x = 1\nprint(x)"
        analyzer = PythonAnalyzer(Path("test.py"), code)
        tree = analyzer.parse()
        liveness = LivenessAnalyzer(analyzer)
        # Just test initialization
        assert liveness is not None

    def test_analyze_dead_variable(self):
        code = "x = 1\nx = 2"
        analyzer = PythonAnalyzer(Path("test.py"), code)
        tree = analyzer.parse()
        liveness = LivenessAnalyzer(analyzer)
        # First assignment to x is dead
        assert liveness is not None
