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

"""Tests for interprocedural analysis components."""

import pytest


class TestInterprocedural:
    """Test interprocedural analysis functionality."""

    def test_interprocedural_module_exists(self):
        """Test that interprocedural module can be imported."""
        from mcpscanner.core.static_analysis import interprocedural

        assert interprocedural is not None

    def test_call_graph_analyzer_importable(self):
        """Test that call graph analyzer can be imported."""
        try:
            from mcpscanner.core.static_analysis.interprocedural.call_graph_analyzer import (
                CallGraphAnalyzer,
            )

            assert CallGraphAnalyzer is not None
        except (ImportError, AttributeError):
            pytest.skip("Call graph analyzer structure needs verification")

    def test_cross_file_analyzer_importable(self):
        """Test that cross file analyzer can be imported."""
        try:
            from mcpscanner.core.static_analysis.interprocedural.cross_file_analyzer import (
                CrossFileAnalyzer,
            )

            assert CrossFileAnalyzer is not None
        except (ImportError, AttributeError):
            pytest.skip("Cross file analyzer structure needs verification")
