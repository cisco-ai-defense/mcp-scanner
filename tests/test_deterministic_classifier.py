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

"""Tests for the deterministic classifier rule engine."""

import pytest

from mcpscanner.core.analyzers.deterministic_classifier import (
    DeterministicClassifier,
    TaintedSubprocessExec,
    TaintedEvalExec,
    TaintedNetworkSend,
    HardcodedExternalURL,
    TaintedFileWrite,
    EnvVarHarvesting,
    DocstringMismatchHeuristic,
    RuleMatch,
)
from mcpscanner.core.static_analysis.context_extractor import FunctionContext


def _make_ctx(**overrides) -> FunctionContext:
    """Create a minimal FunctionContext with overrides."""
    defaults = dict(
        name="test_func",
        decorator_types=["mcp.tool"],
        imports=[],
        function_calls=[],
        assignments=[],
        control_flow={},
        parameter_flows=[],
        constants={},
        variable_dependencies={},
        has_file_operations=False,
        has_network_operations=False,
        has_subprocess_calls=False,
        has_eval_exec=False,
        has_dangerous_imports=False,
        docstring="A test tool",
        parameters=[],
        string_literals=[],
        env_var_access=[],
    )
    defaults.update(overrides)
    return FunctionContext(**defaults)


# ── DET-001: TaintedSubprocessExec ──


class TestTaintedSubprocessExec:
    def test_no_subprocess_calls(self):
        ctx = _make_ctx(has_subprocess_calls=False)
        assert TaintedSubprocessExec().matches(ctx) is None

    def test_subprocess_with_param_flow(self):
        ctx = _make_ctx(
            has_subprocess_calls=True,
            parameters=[{"name": "cmd"}],
            parameter_flows=[
                {
                    "parameter": "cmd",
                    "reaches_calls": ["subprocess.run"],
                    "reaches_assignments": [],
                    "reaches_returns": False,
                    "reaches_external": False,
                }
            ],
        )
        match = TaintedSubprocessExec().matches(ctx)
        assert match is not None
        assert match.rule_id == "DET-001"
        assert match.severity == "HIGH"
        assert "subprocess.run" in match.evidence[0]

    def test_subprocess_with_param_in_args(self):
        ctx = _make_ctx(
            has_subprocess_calls=True,
            parameters=[{"name": "user_input"}],
            parameter_flows=[],
            function_calls=[
                {"name": "subprocess.call", "args": ["user_input"], "line": 10}
            ],
        )
        match = TaintedSubprocessExec().matches(ctx)
        assert match is not None
        assert "user_input" in match.evidence[0]

    def test_subprocess_without_param_flow_no_match(self):
        ctx = _make_ctx(
            has_subprocess_calls=True,
            parameters=[{"name": "x"}],
            parameter_flows=[],
            function_calls=[
                {"name": "subprocess.run", "args": ["'ls'"], "line": 10}
            ],
        )
        match = TaintedSubprocessExec().matches(ctx)
        assert match is None


# ── DET-002: TaintedEvalExec ──


class TestTaintedEvalExec:
    def test_no_eval_exec(self):
        ctx = _make_ctx(has_eval_exec=False)
        assert TaintedEvalExec().matches(ctx) is None

    def test_eval_with_param_flow(self):
        ctx = _make_ctx(
            has_eval_exec=True,
            parameters=[{"name": "code"}],
            parameter_flows=[
                {
                    "parameter": "code",
                    "reaches_calls": ["eval"],
                    "reaches_assignments": [],
                    "reaches_returns": False,
                    "reaches_external": False,
                }
            ],
        )
        match = TaintedEvalExec().matches(ctx)
        assert match is not None
        assert match.rule_id == "DET-002"

    def test_exec_with_param_in_args(self):
        ctx = _make_ctx(
            has_eval_exec=True,
            parameters=[{"name": "expr"}],
            parameter_flows=[],
            function_calls=[{"name": "exec", "args": ["expr"], "line": 5}],
        )
        match = TaintedEvalExec().matches(ctx)
        assert match is not None


# ── DET-003: TaintedNetworkSend ──


class TestTaintedNetworkSend:
    def test_no_network_ops(self):
        ctx = _make_ctx(has_network_operations=False)
        assert TaintedNetworkSend().matches(ctx) is None

    def test_param_reaches_external(self):
        ctx = _make_ctx(
            has_network_operations=True,
            parameters=[{"name": "data"}],
            parameter_flows=[
                {
                    "parameter": "data",
                    "reaches_calls": [],
                    "reaches_assignments": [],
                    "reaches_returns": False,
                    "reaches_external": True,
                }
            ],
        )
        match = TaintedNetworkSend().matches(ctx)
        assert match is not None
        assert match.rule_id == "DET-003"
        assert match.severity == "HIGH"

    def test_param_flows_to_requests_post(self):
        ctx = _make_ctx(
            has_network_operations=True,
            parameters=[{"name": "payload"}],
            parameter_flows=[
                {
                    "parameter": "payload",
                    "reaches_calls": ["requests.post"],
                    "reaches_assignments": [],
                    "reaches_returns": False,
                    "reaches_external": False,
                }
            ],
        )
        match = TaintedNetworkSend().matches(ctx)
        assert match is not None


# ── DET-004: HardcodedExternalURL ──


class TestHardcodedExternalURL:
    def test_no_urls(self):
        ctx = _make_ctx(string_literals=["hello world", "just a string"])
        assert HardcodedExternalURL().matches(ctx) is None

    def test_external_url(self):
        ctx = _make_ctx(
            string_literals=["https://evil.com/exfil", "normal text"]
        )
        match = HardcodedExternalURL().matches(ctx)
        assert match is not None
        assert match.rule_id == "DET-004"
        assert "evil.com" in match.evidence[0]

    def test_localhost_not_flagged(self):
        ctx = _make_ctx(
            string_literals=["http://localhost:8080/api", "http://127.0.0.1:3000"]
        )
        assert HardcodedExternalURL().matches(ctx) is None


# ── DET-005: TaintedFileWrite ──


class TestTaintedFileWrite:
    def test_no_file_ops(self):
        ctx = _make_ctx(has_file_operations=False)
        assert TaintedFileWrite().matches(ctx) is None

    def test_param_flows_to_open(self):
        ctx = _make_ctx(
            has_file_operations=True,
            parameters=[{"name": "path"}],
            parameter_flows=[
                {
                    "parameter": "path",
                    "reaches_calls": ["open"],
                    "reaches_assignments": [],
                    "reaches_returns": False,
                    "reaches_external": False,
                }
            ],
        )
        match = TaintedFileWrite().matches(ctx)
        assert match is not None
        assert match.rule_id == "DET-005"


# ── DET-006: EnvVarHarvesting ──


class TestEnvVarHarvesting:
    def test_no_env_vars(self):
        ctx = _make_ctx(env_var_access=[])
        assert EnvVarHarvesting().matches(ctx) is None

    def test_env_vars_without_network(self):
        ctx = _make_ctx(
            env_var_access=["os.getenv('SECRET_KEY')"],
            has_network_operations=False,
        )
        assert EnvVarHarvesting().matches(ctx) is None

    def test_env_vars_with_network(self):
        ctx = _make_ctx(
            env_var_access=["os.getenv('API_KEY')", "os.environ.get('DB_PASS')"],
            has_network_operations=True,
        )
        match = EnvVarHarvesting().matches(ctx)
        assert match is not None
        assert match.rule_id == "DET-006"
        assert match.severity == "MEDIUM"


# ── DET-007: DocstringMismatchHeuristic ──


class TestDocstringMismatchHeuristic:
    def test_no_docstring(self):
        ctx = _make_ctx(docstring=None)
        assert DocstringMismatchHeuristic().matches(ctx) is None

    def test_calculator_with_network(self):
        ctx = _make_ctx(
            name="add_numbers",
            docstring="A simple calculator that adds two numbers",
            has_network_operations=True,
        )
        match = DocstringMismatchHeuristic().matches(ctx)
        assert match is not None
        assert match.rule_id == "DET-007"
        assert "has_network_operations" in match.evidence[0]

    def test_calculator_without_suspicious_ops(self):
        ctx = _make_ctx(
            name="add_numbers",
            docstring="A simple calculator that adds two numbers",
        )
        assert DocstringMismatchHeuristic().matches(ctx) is None

    def test_greeting_with_subprocess(self):
        ctx = _make_ctx(
            name="say_hello",
            docstring="A simple greeting tool",
            has_subprocess_calls=True,
        )
        match = DocstringMismatchHeuristic().matches(ctx)
        assert match is not None

    def test_read_tool_with_subprocess(self):
        ctx = _make_ctx(
            name="get_data",
            docstring="Reads data from the database",
            has_subprocess_calls=True,
        )
        match = DocstringMismatchHeuristic().matches(ctx)
        assert match is not None


# ── DeterministicClassifier integration ──


class TestDeterministicClassifier:
    def test_empty_context_no_matches(self):
        ctx = _make_ctx()
        classifier = DeterministicClassifier()
        matches = classifier.classify(ctx)
        assert matches == []

    def test_multiple_rules_fire(self):
        ctx = _make_ctx(
            name="calculator",
            docstring="A simple calculator",
            has_eval_exec=True,
            has_network_operations=True,
            parameters=[{"name": "expr"}],
            parameter_flows=[
                {
                    "parameter": "expr",
                    "reaches_calls": ["eval"],
                    "reaches_assignments": [],
                    "reaches_returns": False,
                    "reaches_external": True,
                }
            ],
            string_literals=["https://attacker.com/exfil"],
        )
        classifier = DeterministicClassifier()
        matches = classifier.classify(ctx)
        rule_ids = {m.rule_id for m in matches}
        assert "DET-002" in rule_ids  # TaintedEvalExec
        assert "DET-003" in rule_ids  # TaintedNetworkSend
        assert "DET-004" in rule_ids  # HardcodedExternalURL
        assert "DET-007" in rule_ids  # DocstringMismatch

    def test_determinism(self):
        """Same input must always produce the same output."""
        ctx = _make_ctx(
            has_subprocess_calls=True,
            parameters=[{"name": "cmd"}],
            parameter_flows=[
                {
                    "parameter": "cmd",
                    "reaches_calls": ["subprocess.run"],
                    "reaches_assignments": [],
                    "reaches_returns": False,
                    "reaches_external": False,
                }
            ],
        )
        classifier = DeterministicClassifier()
        results = [classifier.classify(ctx) for _ in range(50)]

        # All runs must be identical
        first = [(m.rule_id, m.threat_name, m.severity) for m in results[0]]
        for i, run in enumerate(results[1:], 1):
            current = [(m.rule_id, m.threat_name, m.severity) for m in run]
            assert current == first, f"Run {i} differs from run 0"

    def test_custom_rules(self):
        classifier = DeterministicClassifier(rules=[TaintedSubprocessExec()])
        ctx = _make_ctx(
            has_eval_exec=True,
            parameters=[{"name": "code"}],
            parameter_flows=[
                {
                    "parameter": "code",
                    "reaches_calls": ["eval"],
                    "reaches_assignments": [],
                    "reaches_returns": False,
                    "reaches_external": False,
                }
            ],
        )
        # Only subprocess rule is loaded, eval should not trigger
        matches = classifier.classify(ctx)
        assert len(matches) == 0
