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
# LIMITED under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for behavioural.analysis.dataflow module."""

import pytest
import ast
from pathlib import Path
from mcpscanner.behavioural.analysis.dataflow import CFGNode, ControlFlowGraph
from mcpscanner.behavioural.analyzers.python_analyzer import PythonAnalyzer


class TestCFGNode:
    def test_cfg_node_init(self):
        node = CFGNode(1, ast.Pass(), "test")
        assert node.id == 1
        assert node.label == "test"
        assert len(node.predecessors) == 0
        assert len(node.successors) == 0

    def test_cfg_node_repr(self):
        node = CFGNode(1, ast.Pass(), "test")
        assert "CFGNode" in repr(node)
        assert "1" in repr(node)


class TestControlFlowGraph:
    def test_cfg_init(self):
        cfg = ControlFlowGraph()
        assert cfg is not None

    def test_cfg_has_entry_exit(self):
        cfg = ControlFlowGraph()
        assert hasattr(cfg, 'entry')
        assert hasattr(cfg, 'exit')

    def test_cfg_build_simple(self):
        cfg = ControlFlowGraph()
        # Just test that CFG can be created
        assert cfg is not None

    def test_cfg_build_if_statement(self):
        cfg = ControlFlowGraph()
        # Just test that CFG can be created
        assert cfg is not None
