# Copyright 2026 Cisco Systems, Inc. and its affiliates
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

"""Regression test for the iteration-cap WARNING in
:mod:`mcpscanner.core.static_analysis.dataflow.treesitter_analysis`."""

from __future__ import annotations

import logging

from mcpscanner.core.static_analysis.cfg.treesitter_builder import (
    TreeSitterCFG,
    TSCFGNode,
)
from mcpscanner.core.static_analysis.dataflow.treesitter_analysis import (
    TreeSitterDataflowAnalysis,
    TSFlowFact,
)


class _CapTriggeringAnalysis(TreeSitterDataflowAnalysis):
    """Subclass that bypasses real AST processing so the worklist
    iteration cap fires deterministically."""

    def __init__(self) -> None:  # noqa: D401
        self.language = "javascript"
        self.facts: dict = {}

    def _get_input_fact(self, node):  # noqa: D401
        return TSFlowFact()

    def _transfer(self, cfg_node, in_fact):  # noqa: D401
        return TSFlowFact()

    def _facts_changed(self, old, new) -> bool:  # noqa: D401
        return True


def _build_self_looping_cfg(successors: int) -> TreeSitterCFG:
    """One-node CFG whose node points back at itself ``successors`` times."""
    cfg = TreeSitterCFG()
    node = TSCFGNode(node_id=0, ast_node=None, node_type="block")  # type: ignore[arg-type]
    cfg.nodes.append(node)
    cfg.entry = node
    node.successors = [node] * successors
    return cfg


class TestTreeSitterIterationCapWarning:
    """Pin the WARNING contract so SIEM rules / dashboards keep working."""

    def test_cap_warning_fires_and_carries_structured_fields(self, caplog, monkeypatch):
        analysis = _CapTriggeringAnalysis()
        analysis.cfg = _build_self_looping_cfg(successors=50)
        analysis.param_names = []

        target = logging.getLogger(
            "mcpscanner.core.static_analysis.dataflow.treesitter_analysis"
        )
        monkeypatch.setattr(target, "propagate", True)

        with caplog.at_level(
            logging.WARNING,
            logger="mcpscanner.core.static_analysis.dataflow.treesitter_analysis",
        ):
            analysis.analyze()

        cap_lines = [
            r.getMessage()
            for r in caplog.records
            if "iteration_cap_hit" in r.getMessage()
        ]
        assert cap_lines, (
            f"expected iteration_cap_hit WARNING in {caplog.text!r}"
        )
        line = cap_lines[0]
        for needle in (
            "static_dataflow treesitter iteration_cap_hit",
            "language=javascript",
            "nodes=1",
            "iterations=",
            "max=10",
            "worklist_remaining=",
        ):
            assert needle in line, f"missing {needle!r} in {line!r}"

    def test_done_line_marks_capped_true_when_cap_fired(self, caplog, monkeypatch):
        analysis = _CapTriggeringAnalysis()
        analysis.cfg = _build_self_looping_cfg(successors=50)
        analysis.param_names = []

        target = logging.getLogger(
            "mcpscanner.core.static_analysis.dataflow.treesitter_analysis"
        )
        monkeypatch.setattr(target, "propagate", True)

        with caplog.at_level(
            logging.DEBUG,
            logger="mcpscanner.core.static_analysis.dataflow.treesitter_analysis",
        ):
            analysis.analyze()

        done_lines = [
            r.getMessage()
            for r in caplog.records
            if "static_dataflow treesitter done" in r.getMessage()
        ]
        assert done_lines, "expected a 'done' DEBUG line"
        assert "capped=True" in done_lines[0]

    def test_no_cap_warning_when_fixpoint_reaches_naturally(self, caplog):
        class _ConvergingAnalysis(_CapTriggeringAnalysis):
            def _facts_changed(self, old, new) -> bool:  # noqa: D401
                return False

        analysis = _ConvergingAnalysis()
        cfg = TreeSitterCFG()
        node = TSCFGNode(node_id=0, ast_node=None, node_type="block")  # type: ignore[arg-type]
        cfg.nodes.append(node)
        cfg.entry = node
        analysis.cfg = cfg
        analysis.param_names = []

        with caplog.at_level(
            logging.WARNING,
            logger="mcpscanner.core.static_analysis.dataflow.treesitter_analysis",
        ):
            analysis.analyze()

        assert not [
            r for r in caplog.records if "iteration_cap_hit" in r.getMessage()
        ], "iteration_cap_hit must not fire on a converging run"
