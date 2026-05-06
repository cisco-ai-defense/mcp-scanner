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

"""Unit tests for the parallelization paths added on top of file caching:

* ``Scanner._run_analyzer_tasks`` — the per-target gather helper used by
  ``_analyze_tool``/``_analyze_prompt``/``_analyze_instructions``/
  ``_analyze_resource``.
* ``AlignmentOrchestrator.check_alignment_batch`` — parallel batch
  dispatch, parseable-failure retry, and per-finding classification gather.

These tests use stubs and ``asyncio`` time tricks rather than real LLM
calls, so they run in well under a second and are safe in CI without
network access.
"""

from __future__ import annotations

import asyncio
import time
import types
from typing import Any, Dict, List, Optional, Tuple
from unittest.mock import AsyncMock, MagicMock

import pytest

from mcpscanner.core.analyzers.base import SecurityFinding
from mcpscanner.core.analyzers.behavioral.alignment.alignment_orchestrator import (
    AlignmentOrchestrator,
)
from mcpscanner.core.scanner import Scanner


# ---------------------------------------------------------------------------
# Scanner._run_analyzer_tasks
# ---------------------------------------------------------------------------


def _make_finding(severity: str = "LOW", summary: str = "f") -> SecurityFinding:
    return SecurityFinding(
        severity=severity,
        summary=summary,
        analyzer="placeholder",
        threat_category="test",
    )


@pytest.mark.asyncio
async def test_run_analyzer_tasks_runs_concurrently_and_tags_findings():
    """All tasks should complete in roughly max(t_i) wall time, and each
    finding's ``analyzer`` attribute must be overwritten with the task's
    analyzer label (preserving the contract the sequential code provided)."""

    async def slow_analyzer(label: str, delay: float) -> List[SecurityFinding]:
        await asyncio.sleep(delay)
        return [_make_finding(summary=label)]

    tasks = [
        ("API", "API analysis", slow_analyzer("from_api", 0.10)),
        ("YARA", "YARA analysis", slow_analyzer("from_yara", 0.10)),
        ("LLM", "LLM analysis", slow_analyzer("from_llm", 0.10)),
    ]

    start = time.monotonic()
    findings, succeeded = await Scanner._run_analyzer_tasks(
        tasks, "tool", "demo"
    )
    elapsed = time.monotonic() - start

    # Concurrent: should be ~0.10s, never close to 0.30s. Allow generous
    # slack for slow CI runners.
    assert elapsed < 0.25, f"expected concurrent execution, took {elapsed:.3f}s"
    assert len(findings) == 3
    assert {f.analyzer for f in findings} == {"API", "YARA", "LLM"}
    assert sorted(succeeded) == ["API", "LLM", "YARA"]


@pytest.mark.asyncio
async def test_run_analyzer_tasks_isolates_exceptions():
    """A raising analyzer must not prevent its peers from contributing
    findings; the failed analyzer's label must be absent from
    ``succeeded``."""

    async def good() -> List[SecurityFinding]:
        return [_make_finding(summary="ok")]

    async def bad() -> List[SecurityFinding]:
        raise RuntimeError("boom")

    tasks = [
        ("API", "API analysis", good()),
        ("LLM", "LLM analysis", bad()),
        ("YARA", "YARA analysis", good()),
    ]

    findings, succeeded = await Scanner._run_analyzer_tasks(
        tasks, "tool", "demo"
    )
    assert len(findings) == 2
    assert sorted(succeeded) == ["API", "YARA"]
    assert "LLM" not in succeeded


@pytest.mark.asyncio
async def test_run_analyzer_tasks_empty_input_returns_empty():
    findings, succeeded = await Scanner._run_analyzer_tasks([], "tool", "demo")
    assert findings == []
    assert succeeded == []


@pytest.mark.asyncio
async def test_run_analyzer_tasks_treats_zero_findings_as_success():
    """An analyzer that returns an empty list is "successful" — its label
    must appear in ``succeeded`` even though it produced no findings.
    This is the behavior custom-analyzer success tracking depends on."""

    async def quiet() -> List[SecurityFinding]:
        return []

    tasks = [
        ("API", "API analysis", quiet()),
    ]
    findings, succeeded = await Scanner._run_analyzer_tasks(
        tasks, "tool", "demo"
    )
    assert findings == []
    assert succeeded == ["API"]


# ---------------------------------------------------------------------------
# AlignmentOrchestrator.check_alignment_batch
# ---------------------------------------------------------------------------


def _stub_func_context(name: str) -> Any:
    """Build a minimal stand-in for ``FunctionContext`` that satisfies what
    the orchestrator reads off it (``.name``)."""
    return types.SimpleNamespace(name=name)


def _make_orchestrator() -> AlignmentOrchestrator:
    """Construct an orchestrator with all collaborators replaced by mocks
    so we can drive its public API without a real LLM."""
    orch = AlignmentOrchestrator.__new__(AlignmentOrchestrator)
    orch.logger = MagicMock()
    orch.prompt_builder = MagicMock()
    orch.prompt_builder.build_batch_prompt = MagicMock(return_value="prompt")
    orch.llm_client = MagicMock()
    orch.llm_client.verify_alignment = AsyncMock(return_value="{}")
    orch.response_validator = MagicMock()
    orch.threat_vuln_classifier = MagicMock()
    orch.threat_vuln_classifier.classify_finding = AsyncMock(
        return_value={"classification": "VULNERABILITY", "confidence": "HIGH"}
    )
    orch.stats = {
        "total_analyzed": 0,
        "mismatches_detected": 0,
        "no_mismatch": 0,
        "skipped_invalid_response": 0,
        "skipped_error": 0,
    }
    return orch


@pytest.mark.asyncio
async def test_check_alignment_batch_runs_batches_concurrently():
    """With ``batch_concurrency >= len(batches)`` and a slow LLM stub, the
    total wall-clock should be ~T_llm rather than ~N*T_llm."""
    orch = _make_orchestrator()

    delay = 0.10

    async def slow_llm(prompt: str) -> str:
        await asyncio.sleep(delay)
        return "{}"

    orch.llm_client.verify_alignment = AsyncMock(side_effect=slow_llm)
    orch.response_validator.validate_batch = MagicMock(
        return_value=[
            {"mismatch_detected": False},
            {"mismatch_detected": False},
        ]
    )

    func_contexts = [_stub_func_context(f"f{i}") for i in range(6)]

    start = time.monotonic()
    results = await orch.check_alignment_batch(
        func_contexts, batch_size=2, batch_concurrency=4, batch_retries=0
    )
    elapsed = time.monotonic() - start

    # 3 batches, each takes ~0.10s. Concurrent → ~0.10s, sequential → ~0.30s.
    assert elapsed < 0.25, f"expected concurrent batches, took {elapsed:.3f}s"
    assert results == []
    assert orch.stats["total_analyzed"] == 6


@pytest.mark.asyncio
async def test_check_alignment_batch_classifies_findings_in_parallel():
    """When a single batch produces multiple mismatches, the per-finding
    classifier calls should be issued via gather rather than sequentially."""
    orch = _make_orchestrator()
    orch.response_validator.validate_batch = MagicMock(
        return_value=[
            {
                "mismatch_detected": True,
                "threat_name": "DATA EXFILTRATION",
                "summary": "x",
            },
            {
                "mismatch_detected": True,
                "threat_name": "DATA EXFILTRATION",
                "summary": "y",
            },
            {
                "mismatch_detected": True,
                "threat_name": "DATA EXFILTRATION",
                "summary": "z",
            },
        ]
    )
    classify_delay = 0.10

    async def slow_classify(**kwargs):
        await asyncio.sleep(classify_delay)
        return {"classification": "VULNERABILITY", "confidence": "HIGH"}

    orch.threat_vuln_classifier.classify_finding = AsyncMock(
        side_effect=slow_classify
    )

    func_contexts = [_stub_func_context(f"f{i}") for i in range(3)]

    start = time.monotonic()
    results = await orch.check_alignment_batch(
        func_contexts, batch_size=3, batch_concurrency=1, batch_retries=0
    )
    elapsed = time.monotonic() - start

    # 3 classifications × ~0.10s; parallel → ~0.10s, sequential → ~0.30s.
    assert elapsed < 0.25, (
        f"classifications expected to run in parallel, took {elapsed:.3f}s"
    )
    assert len(results) == 3
    for analysis, _ctx in results:
        assert analysis["threat_vulnerability_classification"] == "VULNERABILITY"


@pytest.mark.asyncio
async def test_check_alignment_batch_retries_unparseable_response():
    """When ``validate_batch`` returns falsy, the batch should be retried up
    to ``batch_retries`` extra times before any fallback kicks in."""
    orch = _make_orchestrator()

    # First two attempts return falsy (unparseable), third succeeds.
    validate_outputs = [None, [], [{"mismatch_detected": False}]]
    call_count = {"n": 0}

    def validate_side_effect(response, expected_count):
        idx = call_count["n"]
        call_count["n"] += 1
        return validate_outputs[idx]

    orch.response_validator.validate_batch = MagicMock(
        side_effect=validate_side_effect
    )

    func_contexts = [_stub_func_context("f0")]
    results = await orch.check_alignment_batch(
        func_contexts, batch_size=1, batch_concurrency=1, batch_retries=2
    )

    assert results == []
    assert call_count["n"] == 3, (
        f"expected 3 validate_batch calls (1 + 2 retries), got {call_count['n']}"
    )
    # Total analyzed counted once even though the batch was retried.
    assert orch.stats["total_analyzed"] == 1


@pytest.mark.asyncio
async def test_check_alignment_batch_falls_back_to_per_function_on_exhausted_retries():
    """If all retries produce unparseable responses, the orchestrator must
    fall back to ``check_alignment`` per function (using the single-function
    code path) rather than dropping the batch."""
    orch = _make_orchestrator()

    orch.response_validator.validate_batch = MagicMock(return_value=None)

    # Stub check_alignment to return a synthetic mismatch for every input.
    async def fake_check_alignment(func_context):
        return (
            {
                "mismatch_detected": True,
                "threat_name": "GENERAL DESCRIPTION-CODE MISMATCH",
                "summary": "fallback",
            },
            func_context,
        )

    orch.check_alignment = AsyncMock(side_effect=fake_check_alignment)

    func_contexts = [_stub_func_context(f"f{i}") for i in range(2)]
    results = await orch.check_alignment_batch(
        func_contexts, batch_size=2, batch_concurrency=1, batch_retries=1
    )

    # Both functions should yield a fallback result.
    assert len(results) == 2
    # check_alignment should have been called once per function in the
    # batch, not once and then again sequentially.
    assert orch.check_alignment.await_count == 2


@pytest.mark.asyncio
async def test_check_alignment_batch_empty_input_returns_empty_quickly():
    orch = _make_orchestrator()
    results = await orch.check_alignment_batch(
        [], batch_size=5, batch_concurrency=4, batch_retries=1
    )
    assert results == []
    # No LLM call should have been issued for an empty workload.
    orch.llm_client.verify_alignment.assert_not_awaited()


@pytest.mark.asyncio
async def test_check_alignment_batch_skips_classification_for_general_mismatch():
    """``GENERAL DESCRIPTION-CODE MISMATCH`` is a documentation-class finding
    that the existing pipeline intentionally skips classifying. The parallel
    path must preserve that skip."""
    orch = _make_orchestrator()
    orch.response_validator.validate_batch = MagicMock(
        return_value=[
            {
                "mismatch_detected": True,
                "threat_name": "GENERAL DESCRIPTION-CODE MISMATCH",
                "summary": "doc only",
            }
        ]
    )

    func_contexts = [_stub_func_context("f0")]
    results = await orch.check_alignment_batch(
        func_contexts, batch_size=1, batch_concurrency=1, batch_retries=0
    )

    assert len(results) == 1
    analysis, _ctx = results[0]
    # Classifier should NOT have been called for this finding.
    orch.threat_vuln_classifier.classify_finding.assert_not_awaited()
    # And no classification key should have been written either.
    assert "threat_vulnerability_classification" not in analysis
