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

"""Tests for behavioural.analysis.cross_file module."""

import pytest
import tempfile
from pathlib import Path
from mcpscanner.behavioural.analysis.cross_file import CrossFileAnalyzer
from mcpscanner.behavioural.analyzers.python_analyzer import PythonAnalyzer


class TestCrossFileAnalyzer:
    def test_init(self):
        cf_analyzer = CrossFileAnalyzer()
        assert cf_analyzer is not None

    def test_call_graph_init(self):
        from mcpscanner.behavioural.analysis.cross_file import CallGraph
        cg = CallGraph()
        assert cg is not None

    def test_call_graph_add_call(self):
        from mcpscanner.behavioural.analysis.cross_file import CallGraph
        cg = CallGraph()
        cg.add_call("func1", "func2")
        assert cg is not None

    def test_cross_file_analyzer_exists(self):
        cf_analyzer = CrossFileAnalyzer()
        assert hasattr(cf_analyzer, 'call_graph')
