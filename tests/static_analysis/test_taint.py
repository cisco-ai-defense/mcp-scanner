# Copyright 2025 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Tests for taint tracker component"""

from mcpscanner.core.static_analysis.taint.tracker import ShapeEnvironment, Taint


class TestTaintTracker:
    def test_taint_types_exist(self) -> None:
        assert Taint is not None
        assert ShapeEnvironment is not None
