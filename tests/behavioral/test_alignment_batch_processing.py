# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Behavior of a single alignment batch: caching, fallbacks, and tallies.

_process_alignment_batch is the one place that decides what happens when a
batched LLM call goes wrong, and every one of those answers is a fallback:
an unparseable response re-asks per function, a raised exception re-asks per
function, a failed threat classification degrades to UNCLEAR rather than
dropping the finding. None of that is exercised by the happy-path batch
test, so it is pinned here.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from mcpscanner.config.constants import MCPScannerConstants
from mcpscanner.core.analyzers.behavioral.alignment.alignment_orchestrator import (
    AlignmentOrchestrator,
)
from tests.behavioral.test_code_review_fixes import _cfg


def _ctx(name: str) -> SimpleNamespace:
    return SimpleNamespace(name=name, source_file="srv.py")


def _mismatch(threat: str = "DATA EXFILTRATION") -> dict:
    return {
        "mismatch_detected": True,
        "threat_name": threat,
        "summary": "s",
        "description_claims": "claims",
        "actual_behavior": "behavior",
        "security_implications": "implications",
    }


CLEAN = {"mismatch_detected": False}
UNANALYSED = {"mismatch_detected": False, "_unanalysed": True}


@pytest.fixture
def orch(monkeypatch):
    """An orchestrator whose LLM, prompt builder, and validator are stubs."""
    monkeypatch.setattr(MCPScannerConstants, "ALIGNMENT_CACHE_ENABLED", False)
    o = AlignmentOrchestrator(_cfg())
    o.prompt_builder = SimpleNamespace(
        build_batch_analysis_content=lambda batch: f"body:{len(batch)}",
        wrap_batch_prompt=lambda batch, body: body,
        build_prompt=lambda _c: "p",
    )
    o.llm_client = SimpleNamespace(
        verify_alignment=_unexpected_call, _model="stub-model"
    )
    return o


async def _unexpected_call(*args, **kwargs):
    raise AssertionError("the LLM should not have been called")


def _respond(orch, *, attempts, calls=None):
    """Stub the LLM; ``attempts`` gives one validator result per parse attempt."""
    seen = {"n": 0}

    async def verify(prompt, max_retries=None):
        if calls is not None:
            calls.append(max_retries)
        return "raw"

    def validate_batch(_response, count):
        i = min(seen["n"], len(attempts) - 1)
        seen["n"] += 1
        return attempts[i]

    orch.llm_client = SimpleNamespace(verify_alignment=verify, _model="stub-model")
    orch.response_validator.validate_batch = validate_batch


async def _run(orch, contexts):
    return await orch._process_alignment_batch(contexts, batch_idx=1, total_batches=1)


@pytest.mark.asyncio
async def test_tallies_mismatches_and_clean_results(orch):
    orch.threat_vuln_classifier = SimpleNamespace(
        classify_finding=_classifier("VULNERABILITY")
    )
    _respond(orch, attempts=[[_mismatch(), CLEAN, _mismatch()]])

    results = await _run(orch, [_ctx("a"), _ctx("b"), _ctx("c")])

    assert [c.name for _, c in results] == ["a", "c"]
    assert orch.stats["total_analyzed"] == 3
    assert orch.stats["mismatches_detected"] == 2
    assert orch.stats["no_mismatch"] == 1


def _classifier(value):
    async def classify_finding(**kwargs):
        return {"classification": value}

    return classify_finding


@pytest.mark.asyncio
async def test_unanalysed_verdict_marks_function_errored(orch):
    _respond(orch, attempts=[[UNANALYSED, CLEAN]])

    results = await _run(orch, [_ctx("a"), _ctx("b")])

    assert results == []
    assert orch.stats["skipped_invalid_response"] == 1
    assert orch.alignment_failed(_ctx("a"))
    assert not orch.alignment_failed(_ctx("b"))


@pytest.mark.asyncio
async def test_unparseable_response_falls_back_to_individual_checks(orch):
    _respond(orch, attempts=[None])
    checked = []

    async def check_alignment(ctx):
        checked.append(ctx.name)
        return ({"mismatch_detected": True}, ctx)

    orch.check_alignment = check_alignment

    results = await _run(orch, [_ctx("a"), _ctx("b")])

    assert checked == ["a", "b"]
    assert [c.name for _, c in results] == ["a", "b"]


@pytest.mark.asyncio
async def test_parse_retry_succeeds_on_second_attempt(orch, monkeypatch):
    monkeypatch.setattr(MCPScannerConstants, "LLM_BATCH_PARSE_MAX_ATTEMPTS", 2)
    monkeypatch.setattr(MCPScannerConstants, "LLM_RETRY_BASE_DELAY", 0)
    calls = []
    _respond(orch, attempts=[None, [CLEAN]], calls=calls)

    results = await _run(orch, [_ctx("a")])

    assert results == []
    assert orch.stats["no_mismatch"] == 1
    # The retry asks the client not to layer its own retries on top.
    assert calls == [None, 1]


@pytest.mark.asyncio
async def test_llm_exception_falls_back_to_individual_checks(orch):
    async def boom(prompt, max_retries=None):
        raise RuntimeError("upstream exploded")

    orch.llm_client = SimpleNamespace(verify_alignment=boom, _model="stub-model")
    checked = []

    async def check_alignment(ctx):
        checked.append(ctx.name)
        return None

    orch.check_alignment = check_alignment

    results = await _run(orch, [_ctx("a"), _ctx("b")])

    assert checked == ["a", "b"]
    assert results == []


@pytest.mark.asyncio
async def test_classifier_failure_degrades_to_unclear(orch):
    async def boom(**kwargs):
        raise RuntimeError("classifier down")

    orch.threat_vuln_classifier = SimpleNamespace(classify_finding=boom)
    _respond(orch, attempts=[[_mismatch()]])

    results = await _run(orch, [_ctx("a")])

    assert results[0][0]["threat_vulnerability_classification"] == "UNCLEAR"


@pytest.mark.asyncio
async def test_empty_classification_degrades_to_unclear(orch):
    async def none_result(**kwargs):
        return None

    orch.threat_vuln_classifier = SimpleNamespace(classify_finding=none_result)
    _respond(orch, attempts=[[_mismatch()]])

    results = await _run(orch, [_ctx("a")])

    assert results[0][0]["threat_vulnerability_classification"] == "UNCLEAR"


@pytest.mark.asyncio
async def test_generic_mismatch_skips_classification(orch):
    orch.threat_vuln_classifier = SimpleNamespace(classify_finding=_unexpected_call)
    _respond(orch, attempts=[[_mismatch("GENERAL DESCRIPTION-CODE MISMATCH")]])

    results = await _run(orch, [_ctx("a")])

    assert "threat_vulnerability_classification" not in results[0][0]
    assert orch.stats["mismatches_detected"] == 1


@pytest.mark.asyncio
async def test_surplus_verdicts_beyond_batch_size_are_ignored(orch):
    # A model that returns more verdicts than functions must not index past
    # the batch and mis-attribute a finding to the wrong function.
    _respond(orch, attempts=[[CLEAN, CLEAN, CLEAN]])

    results = await _run(orch, [_ctx("a")])

    assert results == []
    assert orch.stats["total_analyzed"] == 1


@pytest.mark.asyncio
async def test_fully_cached_batch_never_calls_the_llm(orch, monkeypatch):
    monkeypatch.setattr(MCPScannerConstants, "ALIGNMENT_CACHE_ENABLED", True)
    orch.llm_client = SimpleNamespace(
        verify_alignment=_unexpected_call, _model="stub-model"
    )
    monkeypatch.setattr(
        orch, "_cache_lookup", lambda ctx: ({"mismatch_detected": True}, "k")
    )

    results = await _run(orch, [_ctx("a"), _ctx("b")])

    assert [c.name for _, c in results] == ["a", "b"]
    assert orch.stats["cache_hits"] == 2
