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

"""Tests for behavioural.analysis.typing module."""

import pytest
from pathlib import Path
from mcpscanner.behavioural.analysis.typing import TypeAnalyzer, Type, TypeKind
from mcpscanner.behavioural.analyzers.python_analyzer import PythonAnalyzer


class TestTypeAnalyzer:
    def test_init(self):
        code = "x = 1"
        analyzer = PythonAnalyzer(Path("test.py"), code)
        analyzer.parse()
        type_analyzer = TypeAnalyzer(analyzer)
        assert type_analyzer.analyzer == analyzer

    def test_type_kind_enum(self):
        assert TypeKind.INT.value == "int"
        assert TypeKind.STR.value == "str"
        assert TypeKind.UNKNOWN.value == "unknown"

    def test_type_creation(self):
        int_type = Type(TypeKind.INT)
        assert int_type.kind == TypeKind.INT

    def test_type_equality(self):
        type1 = Type(TypeKind.INT)
        type2 = Type(TypeKind.INT)
        assert type1 == type2
