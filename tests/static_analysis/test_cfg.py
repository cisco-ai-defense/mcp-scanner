# Copyright 2025 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Tests for CFG builder component"""

from mcpscanner.core.static_analysis.cfg.builder import ControlFlowGraph, DataFlowAnalyzer


class TestCFGBuilder:
    def test_control_flow_graph_exists(self) -> None:
        assert ControlFlowGraph is not None

    def test_data_flow_analyzer_exists(self) -> None:
        assert DataFlowAnalyzer is not None
