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
:mod:`mcpscanner.core.static_analysis.dataflow.treesitter_analysis`.

Pre-fix, when the worklist algorithm hit the hard-coded iteration limit
it silently bailed out with whatever facts it had accumulated. That
meant any dataflow analysis stuck under the cap produced quietly
truncated results, with no operator-facing signal to explain why a
subsequent finding was missing context.

The fix surfaces a WARNING with the language, CFG size, and worklist
state so operators can see the cap firing and either tune limits or
investigate the offending source file. This test pins the WARNING's
exact field names so a future copy edit can't quietly turn it back
into prose.
"""

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
    """Subclass that bypasses real AST processing.

    The production class walks tree-sitter AST children inside
    ``_transfer``; that's expensive to set up in a unit test (requires
    parsing real source). Here we short-circuit the transfer function
    so the test focuses on the worklist loop's *control flow* — which
    is what the iteration-cap WARNING reports on.

    ``_facts_changed`` is forced to ``True`` on every step so the loop
    keeps re-adding successors to the worklist, allowing the cap to
    trigger predictably regardless of taint shape.
    """

    def __init__(self) -> None:  # noqa: D401 — bypass parent __init__
        # The real ``__init__`` invokes ``TreeSitterCFGBuilder.build``
        # on a real tree-sitter Node. We're testing the analyse-loop's
        # cap behaviour in isolation so we install fakes directly.
        self.language = "javascript"
        self.facts: dict = {}

    # The three hooks the production worklist calls. Stubbed so the
    # loop terminates only when the iteration cap fires, never via
    # natural fixpoint.
    def _get_input_fact(self, node):  # noqa: D401
        return TSFlowFact()

    def _transfer(self, cfg_node, in_fact):  # noqa: D401
        return TSFlowFact()

    def _facts_changed(self, old, new) -> bool:  # noqa: D401
        return True


def _build_self_looping_cfg(successors: int) -> TreeSitterCFG:
    """Construct a one-node CFG whose single node points back at itself
    ``successors`` times.

    With one node the cap is ``len(self.cfg.nodes) * 10 == 10``; setting
    ``successors`` well above that guarantees the worklist still has
    pending entries when the cap fires.
    """
    cfg = TreeSitterCFG()
    # ``ast_node`` and ``node_type`` are referenced for logging but the
    # subclass above doesn't dereference them, so a sentinel is fine.
    node = TSCFGNode(node_id=0, ast_node=None, node_type="block")  # type: ignore[arg-type]
    cfg.nodes.append(node)
    cfg.entry = node
    # Self-reference so visiting node 0 adds N more copies of node 0
    # to the worklist; the visited-set short-circuits them, but each
    # ``continue`` still increments ``iterations``.
    node.successors = [node] * successors
    return cfg


class TestTreeSitterIterationCapWarning:
    """Pin the WARNING contract so SIEM rules / dashboards keep working."""

    def test_cap_warning_fires_and_carries_structured_fields(self, caplog):
        analysis = _CapTriggeringAnalysis()
        analysis.cfg = _build_self_looping_cfg(successors=50)
        analysis.param_names = []  # no params; entry fact is empty

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
        # These field names are the structured contract; operators
        # filter on them in Splunk/CloudWatch.
        for needle in (
            "static_dataflow treesitter iteration_cap_hit",
            "language=javascript",
            "nodes=1",
            "iterations=",
            "max=10",
            "worklist_remaining=",
        ):
            assert needle in line, f"missing {needle!r} in {line!r}"

    def test_done_line_marks_capped_true_when_cap_fired(self, caplog):
        """The ``static_dataflow treesitter done`` DEBUG line should
        carry ``capped=True`` so observers downstream of the WARNING
        know the result was truncated.
        """
        analysis = _CapTriggeringAnalysis()
        analysis.cfg = _build_self_looping_cfg(successors=50)
        analysis.param_names = []

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
        """A normal run that converges before the cap MUST NOT emit
        the WARNING — otherwise the line becomes alert noise.
        """

        class _ConvergingAnalysis(_CapTriggeringAnalysis):
            # Override so the loop terminates the very first iteration:
            # report ``no change`` for every step, which leaves the
            # worklist alone after the initial successors are popped.
            def _facts_changed(self, old, new) -> bool:  # noqa: D401
                return False

        analysis = _ConvergingAnalysis()
        # No self-loop: a tiny non-cyclic graph reaches fixpoint
        # immediately.
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
