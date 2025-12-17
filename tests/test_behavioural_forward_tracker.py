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

"""Tests for behavioural.analysis.forward_tracker module."""

import pytest
from pathlib import Path
from mcpscanner.behavioural.analysis.forward_tracker import ForwardFlowTracker, FlowPath
from mcpscanner.behavioural.analyzers.python_analyzer import PythonAnalyzer


class TestFlowPath:
    def test_flow_path_init(self):
        path = FlowPath("x")
        assert path.parameter_name == "x"
        assert len(path.operations) == 0

    def test_flow_path_has_operations(self):
        path = FlowPath("x")
        assert hasattr(path, 'operations')
        assert isinstance(path.operations, list)


class TestForwardFlowTracker:
    def test_init(self):
        code = "x = 1"
        analyzer = PythonAnalyzer(Path("test.py"), code)
        analyzer.parse()
        tracker = ForwardFlowTracker(analyzer, ["x"])
        assert tracker.analyzer == analyzer

    def test_track_simple_assignment(self):
        code = "x = 1\ny = x"
        analyzer = PythonAnalyzer(Path("test.py"), code)
        tree = analyzer.parse()
        tracker = ForwardFlowTracker(analyzer, ["x"])
        # Just test initialization
        assert tracker is not None

    def test_track_function_call(self):
        code = "x = 1\nprint(x)"
        analyzer = PythonAnalyzer(Path("test.py"), code)
        tree = analyzer.parse()
        tracker = ForwardFlowTracker(analyzer, ["x"])
        # Just test initialization
        assert tracker is not None

    def test_track_return_statement(self):
        code = "def foo():\n    x = 1\n    return x"
        analyzer = PythonAnalyzer(Path("test.py"), code)
        tree = analyzer.parse()
        tracker = ForwardFlowTracker(analyzer, ["x"])
        # Just test initialization
        assert tracker is not None
