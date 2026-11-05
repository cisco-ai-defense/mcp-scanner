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

"""CAPABILITY_RISK requires a parameter-to-sink fact, not prose."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from mcpscanner.config.config import Config
from mcpscanner.core.analyzers.behavioral.alignment.alignment_orchestrator import (
    AlignmentOrchestrator,
)
from mcpscanner.core.analyzers.behavioral.alignment.alignment_response_validator import (
    apply_capability_risk_contract,
)

SINK = "subprocess.run"


def _cfg() -> Config:
    return Config(llm_model="gpt-4o", llm_provider_api_key="test-key")


def _flows(parameter: str, calls: list[str]) -> list[dict]:
    return [
        {
            "parameter_name": parameter,
            "reaches_calls": list(calls),
            "operations": [
                {
                    "type": "function_call",
                    "function": call,
                    "argument": parameter,
                }
                for call in calls
            ],
        }
    ]


def _ctx(name: str, flows: list[dict]) -> SimpleNamespace:
    return SimpleNamespace(name=name, parameter_flows=flows)


def _payload(**extra) -> dict:
    body = {
        "mismatch_detected": True,
        "finding_class": "CAPABILITY_RISK",
        "threat_name": "INJECTION ATTACKS",
        "summary": "parameter reaches a shell",
    }
    body.update(extra)
    return body


def _orch(response: str) -> AlignmentOrchestrator:
    orch = AlignmentOrchestrator(_cfg())

    async def verify(_prompt, max_retries=None):
        return response

    async def classify(**_kwargs):
        return {"classification": "VULNERABILITY", "confidence": "high"}

    orch.prompt_builder = SimpleNamespace(
        build_prompt=lambda _ctx: "prompt",
        build_batch_analysis_content=lambda _batch: "batch",
        wrap_batch_prompt=lambda _batch, body: body,
    )
    orch.llm_client = SimpleNamespace(verify_alignment=verify)
    orch.threat_vuln_classifier = SimpleNamespace(classify_finding=classify)
    return orch


def test_supported_claim_is_kept_and_normalized():
    analysis = _payload(
        reachability_evidence={"parameter": "command", "sink": SINK},
        dataflow_evidence="prose that must not be the proof",
    )
    ctx = _ctx("run_cmd", _flows("command", [SINK]))
    assert apply_capability_risk_contract(analysis, ctx) is True
    assert analysis["reachability_evidence"] == [
        {"parameter": "command", "sink": SINK}
    ]


def test_prose_mentioning_the_sink_is_not_proof():
    analysis = _payload(
        dataflow_evidence=(
            "Parameter 'command' flows unmodified to subprocess.run"
        )
    )
    ctx = _ctx("run_cmd", _flows("command", [SINK]))
    assert apply_capability_risk_contract(analysis, ctx) is False


def test_sink_unrelated_to_the_claimed_parameter_is_rejected():
    """The same sink exists, but the MCP parameter does not reach it."""
    analysis = _payload(
        reachability_evidence={"parameter": "command", "sink": SINK}
    )
    flows = _flows("command", ["print"]) + _flows("label", [SINK])
    assert apply_capability_risk_contract(analysis, _ctx("run_cmd", flows)) is False


@pytest.mark.parametrize(
    "evidence",
    [None, "", [], {}, {"parameter": "command", "sink": ""}, {"sink": SINK}],
)
def test_missing_or_empty_evidence_is_rejected(evidence):
    extra = {}
    if evidence is not None:
        extra["reachability_evidence"] = evidence
    analysis = _payload(**extra)
    ctx = _ctx("run_cmd", _flows("command", [SINK]))
    assert apply_capability_risk_contract(analysis, ctx) is False


def test_other_finding_classes_do_not_require_reachability():
    analysis = _payload(finding_class="MALICIOUS_BEHAVIOR")
    analysis.pop("reachability_evidence", None)
    assert apply_capability_risk_contract(analysis, _ctx("run_cmd", [])) is True


def test_dotted_suffix_matches_recorded_call_name():
    analysis = _payload(
        reachability_evidence={"parameter": "command", "sink": "subprocess.run"}
    )
    flows = _flows("command", ["run"])
    assert apply_capability_risk_contract(analysis, _ctx("run_cmd", flows)) is True


def test_unrelated_leaf_does_not_match():
    analysis = _payload(
        reachability_evidence={"parameter": "query", "sink": "exec"}
    )
    flows = _flows("query", ["executeQuery"])
    assert apply_capability_risk_contract(analysis, _ctx("search", flows)) is False


def test_external_sink_recorded_on_a_callee_is_enough():
    analysis = _payload(
        reachability_evidence={"parameter": "command", "sink": "subprocess.run"}
    )
    flows = [
        {
            "parameter_name": "command",
            "reaches_calls": ["ShellExecutor.execute_command"],
            "reaches_external": True,
            "external_sinks": ["subprocess.run"],
            "operations": [],
        }
    ]
    assert apply_capability_risk_contract(analysis, _ctx("run_cmd", flows)) is True


def test_treesitter_call_operation_is_enough():
    analysis = _payload(
        reachability_evidence={"parameter": "command", "sink": "exec"}
    )
    flows = [
        {
            "parameter_name": "command",
            "reaches_calls": [],
            "operations": [{"type": "call", "function": "child_process.exec"}],
        }
    ]
    assert apply_capability_risk_contract(analysis, _ctx("run_cmd", flows)) is True


def test_function_call_operation_is_enough_when_reaches_calls_is_empty():
    analysis = _payload(
        reachability_evidence={"parameter": "command", "sink": SINK}
    )
    flows = [
        {
            "parameter": "command",
            "reaches_calls": [],
            "operations": [
                {"type": "function_call", "function": SINK, "argument": "command"}
            ],
        }
    ]
    assert apply_capability_risk_contract(analysis, _ctx("run_cmd", flows)) is True


@pytest.mark.asyncio
async def test_individual_supported_path_returns_capability_risk():
    evidence = {"parameter": "command", "sink": SINK}
    orch = _orch(json.dumps(_payload(reachability_evidence=evidence)))
    ctx = _ctx("run_cmd", _flows("command", [SINK]))

    result = await orch.check_alignment(ctx)

    assert result is not None
    analysis, returned = result
    assert analysis["finding_class"] == "CAPABILITY_RISK"
    assert analysis["reachability_evidence"] == [
        {"parameter": "command", "sink": SINK}
    ]
    assert returned is ctx
    assert orch.errored_function_names == set()
    assert orch.stats["mismatches_detected"] == 1
    assert orch.stats["no_mismatch"] == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "extra",
    [
        {"dataflow_evidence": "command reaches subprocess.run"},
        {"reachability_evidence": {"parameter": "command", "sink": SINK}},
        {},
    ],
)
async def test_individual_unsupported_path_is_errored_not_clean(extra):
    flows = _flows("command", ["print"])
    if "dataflow_evidence" in extra:
        flows = _flows("command", [SINK])
    orch = _orch(json.dumps(_payload(**extra)))

    result = await orch.check_alignment(_ctx("run_cmd", flows))

    assert result is None
    assert orch.errored_function_names == {"run_cmd"}
    assert orch.stats["no_mismatch"] == 0
    assert orch.stats["mismatches_detected"] == 0
    assert orch.stats["skipped_invalid_response"] == 1


@pytest.mark.asyncio
async def test_individual_malicious_behavior_does_not_need_reachability():
    payload = _payload(
        finding_class="MALICIOUS_BEHAVIOR",
        threat_name="DATA EXFILTRATION",
    )
    orch = _orch(json.dumps(payload))
    result = await orch.check_alignment(_ctx("steal", []))
    assert result is not None
    assert result[0]["finding_class"] == "MALICIOUS_BEHAVIOR"
    assert orch.errored_function_names == set()


@pytest.mark.asyncio
async def test_batch_keeps_only_supported_capability_risk():
    contexts = [
        _ctx("reachable", _flows("command", [SINK])),
        _ctx("unrelated", _flows("command", ["print"]) + _flows("label", [SINK])),
        _ctx("malformed", _flows("command", [SINK])),
        _ctx("omitted", _flows("command", [SINK])),
    ]
    items = [
        _payload(reachability_evidence={"parameter": "command", "sink": SINK}),
        _payload(
            dataflow_evidence="label reaches subprocess.run but command does not",
            reachability_evidence={"parameter": "command", "sink": SINK},
        ),
        {"mismatch_detected": True},
    ]
    orch = _orch(json.dumps(items))

    results = await orch.check_alignment_batch(contexts, batch_size=4)

    assert [ctx.name for _analysis, ctx in results] == ["reachable"]
    assert results[0][0]["reachability_evidence"] == [
        {"parameter": "command", "sink": SINK}
    ]
    assert orch.errored_function_names == {"unrelated", "malformed", "omitted"}
    assert orch.stats["mismatches_detected"] == 1
    assert orch.stats["no_mismatch"] == 0
    assert orch.stats["skipped_invalid_response"] == 3


@pytest.mark.asyncio
async def test_js_rejected_capability_is_inconclusive(monkeypatch):
    from unittest.mock import patch

    from mcpscanner.core.analyzers.behavioral.js_code_analyzer import (
        JSBehavioralCodeAnalyzer,
    )

    analyzer = JSBehavioralCodeAnalyzer(_cfg())

    async def reject(ctx):
        analyzer.alignment_orchestrator.errored_function_names.add(ctx.name)
        return None

    monkeypatch.setattr(analyzer.alignment_orchestrator, "check_alignment", reject)
    with patch(
        "mcpscanner.core.static_analysis.native_analyzer.NativeAnalyzer"
    ) as native:
        native.return_value.extract_mcp_capability_contexts.return_value = [
            _ctx("run_cmd", _flows("command", [SINK]))
        ]
        findings = await analyzer._analyze_source_code(
            "export {}",
            "server.ts",
            {"use_batching": False},
        )
        assert len(findings) == 1
        assert findings[0].severity == "UNKNOWN"
        assert (findings[0].details or {}).get("analysis_status") == "errored"
        assert (findings[0].details or {}).get("function_name") == "run_cmd"

        native.return_value.extract_mcp_capability_contexts.return_value = [
            _ctx("run_cmd", _flows("command", ["print"]))
        ]

        async def clean(_ctx_obj):
            return None

        monkeypatch.setattr(
            analyzer.alignment_orchestrator, "check_alignment", clean
        )
        later = await analyzer._analyze_source_code(
            "export {}",
            "other.ts",
            {"use_batching": False},
        )
    assert later == []


@pytest.mark.asyncio
async def test_python_errored_names_do_not_cross_files(monkeypatch):
    from mcpscanner.core.analyzers.behavioral.code_analyzer import (
        BehavioralCodeAnalyzer,
    )

    analyzer = BehavioralCodeAnalyzer(_cfg())
    state = {"fail": True}

    async def check(ctx):
        if state["fail"]:
            analyzer.alignment_orchestrator.errored_function_names.add(ctx.name)
        return None

    monkeypatch.setattr(
        analyzer.alignment_orchestrator, "check_alignment", check
    )
    source = (
        "from mcp.server.fastmcp import FastMCP\n"
        'mcp = FastMCP("test")\n'
        "@mcp.tool()\n"
        "def captured_tool(x: str) -> str:\n"
        '    """Docstring."""\n'
        "    return x\n"
    )
    first = await analyzer._analyze_source_code(
        source, {"file_path": "a.py", "use_batching": False}
    )
    state["fail"] = False
    second = await analyzer._analyze_source_code(
        source, {"file_path": "b.py", "use_batching": False}
    )

    def named(findings):
        return [
            finding
            for finding in findings
            if (finding.details or {}).get("function_name") == "captured_tool"
        ]

    assert [finding.severity for finding in named(first)] == ["UNKNOWN"]
    assert [finding.severity for finding in named(second)] == ["SAFE"]
