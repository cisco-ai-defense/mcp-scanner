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

"""Equivalence test for the parameterless-capability short-circuit in
:meth:`ForwardDataflowAnalysis.analyze_forward_flows`.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import List

from mcpscanner.core.static_analysis.dataflow.forward_analysis import (
    FlowPath,
    ForwardDataflowAnalysis,
    ForwardFlowFact,
)
from mcpscanner.core.static_analysis.parser.python_parser import PythonParser
from mcpscanner.core.static_analysis.taint.tracker import Taint, TaintStatus


_NO_PARAM_SOURCE = """
def get_status():
    state = "ready"
    return state
"""


def _make_parser() -> PythonParser:
    """Build and parse the fixture parser used by these tests."""
    parser = PythonParser(Path("no_params.py"), _NO_PARAM_SOURCE)
    parser.parse()
    return parser


def _make_analyzer() -> ForwardDataflowAnalysis:
    """Build a ForwardDataflowAnalysis for the no-param fixture."""
    return ForwardDataflowAnalysis(_make_parser(), parameter_names=[])


class _NoShortCircuit(ForwardDataflowAnalysis):
    """ForwardDataflowAnalysis variant that runs the full CFG path even
    when there are no parameters."""

    def analyze_forward_flows(self) -> List[FlowPath]:  # type: ignore[override]
        self.build_cfg()

        initial_fact = ForwardFlowFact()
        for param_name in self.parameter_names:
            taint = Taint(status=TaintStatus.TAINTED)
            taint.add_label(f"param:{param_name}")
            initial_fact.shape_env.set_taint(param_name, taint)
            initial_fact.parameter_flows[param_name] = FlowPath(parameter_name=param_name)

        self.analyze(initial_fact, forward=True)
        self._collect_flows()
        return self.all_flows


class TestForwardFlowsNoParamsEquivalence:
    """Pins the short-circuit's return value to match the long path."""

    def test_short_circuit_returns_empty_and_skips_cfg(self):
        analyzer = _make_analyzer()
        flows = analyzer.analyze_forward_flows()
        assert flows == []
        assert analyzer.cfg is None, "short-circuit must not build a CFG"

    def test_long_path_also_returns_empty_with_cfg_built(self):
        analyzer = _NoShortCircuit(_make_parser(), parameter_names=[])
        flows = analyzer.analyze_forward_flows()
        assert flows == []
        assert analyzer.cfg is not None, "long path must build a CFG"
        assert len(analyzer.cfg.nodes) > 0

    def test_two_paths_agree_on_public_return(self):
        short = _make_analyzer().analyze_forward_flows()
        long_analyzer = _NoShortCircuit(_make_parser(), parameter_names=[])
        long_path = long_analyzer.analyze_forward_flows()
        assert short == long_path == []

    def test_skipped_debug_log_emits_structured_fields(self, caplog, monkeypatch):
        analyzer = _make_analyzer()
        target_logger = logging.getLogger(
            "mcpscanner.core.static_analysis.dataflow.forward_analysis"
        )
        monkeypatch.setattr(target_logger, "propagate", True)
        with caplog.at_level(
            logging.DEBUG,
            logger="mcpscanner.core.static_analysis.dataflow.forward_analysis",
        ):
            analyzer.analyze_forward_flows()

        matching = [
            r for r in caplog.records
            if "static_dataflow forward_flows skipped" in r.getMessage()
        ]
        assert matching, "expected a 'skipped' DEBUG record"
        msg = matching[0].getMessage()
        assert "reason=no_parameters" in msg
        assert "duration_us=" in msg
        assert "file=" in msg
