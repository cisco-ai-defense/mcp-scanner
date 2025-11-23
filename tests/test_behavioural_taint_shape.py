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

"""Tests for behavioural.analysis.taint_shape module."""

import pytest
from pathlib import Path
from mcpscanner.behavioural.analysis.taint_shape import TaintShape, Taint, TaintStatus
from mcpscanner.behavioural.analyzers.python_analyzer import PythonAnalyzer


class TestTaintShape:
    def test_taint_init(self):
        taint = Taint()
        assert taint.status == TaintStatus.UNTAINTED
        assert len(taint.labels) == 0

    def test_taint_status(self):
        taint = Taint(status=TaintStatus.TAINTED)
        assert taint.status == TaintStatus.TAINTED

    def test_taint_shape_init(self):
        shape = TaintShape()
        assert shape is not None

    def test_taint_shape_with_taint(self):
        taint = Taint(status=TaintStatus.TAINTED)
        shape = TaintShape(taint)
        assert shape is not None
