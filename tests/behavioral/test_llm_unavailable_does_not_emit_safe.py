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

"""Regression tests for the LLM-unavailable / silent-failure bug.

Background
----------
Prior to the ``LLM_UNAVAILABLE_KEY`` sentinel work, ``AlignmentOrchestrator``
swallowed exceptions from ``AlignmentLLMClient.verify_alignment`` in two
places — ``check_alignment`` returned ``None`` on any failure, and
``check_alignment_batch`` had a bare ``except Exception: pass`` around its
fallback path. ``BehavioralCodeAnalyzer`` then synthesised a SAFE row for
every function the orchestrator didn't return a finding for, conflating
"verified clean" with "couldn't verify". Operators saw all-SAFE findings
artifacts even when the Bedrock model id was invalid or the provider was
unreachable.

These tests lock the new contract:

1. ``check_alignment`` returns a ``(sentinel, ctx)`` tuple — not ``None``
   — when ``verify_alignment`` raises.
2. ``check_alignment_batch`` emits one sentinel per function in the batch
   when the batch path fails, instead of dropping the batch silently.
3. End-to-end: ``BehavioralCodeAnalyzer.analyze`` returns ``severity="ERROR"``
   findings (one per function) and zero ``severity="SAFE"`` findings when
   the LLM provider is unreachable.
"""

import os
import tempfile
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcpscanner.config import Config
from mcpscanner.core.analyzers.base import SecurityFinding
from mcpscanner.core.analyzers.behavioral.alignment.alignment_orchestrator import (
    LLM_UNAVAILABLE_KEY,
    AlignmentOrchestrator,
)
from mcpscanner.core.analyzers.behavioral.code_analyzer import BehavioralCodeAnalyzer


_TWO_TOOL_MCP_SOURCE = '''
import mcp

@mcp.tool()
def echo(text: str) -> str:
    """Return the provided text unchanged."""
    return text

@mcp.tool()
def add(a: float, b: float) -> float:
    """Return the sum of two finite numbers."""
    return a + b
'''


def _func_context(name: str, line_number: int) -> MagicMock:
    """Build a minimal FunctionContext stub for orchestrator-level tests.

    The orchestrator only reads ``name``, ``line_number``, and the
    ``decorator_types`` list when constructing log messages and stats
    keys, so a MagicMock with those attributes set is sufficient. Using
    a real ``FunctionContext`` would force the test to also build all
    the dataflow-analysis fields the prompt builder expects, which is
    out of scope for a verification-failure regression test.
    """
    fc = MagicMock()
    fc.name = name
    fc.line_number = line_number
    fc.decorator_types = ["mcp.tool"]
    return fc


@pytest.fixture
def orchestrator() -> AlignmentOrchestrator:
    """Build an AlignmentOrchestrator wired to a stub LLM client.

    Uses ``Config(llm_provider_api_key="test-key")`` because the
    constructor enforces an API key for non-Bedrock providers. The
    actual LLM call site is patched in each test, so the key value is
    never used.
    """
    return AlignmentOrchestrator(Config(llm_provider_api_key="test-key"))


class TestCheckAlignmentReturnsSentinelOnLLMFailure:
    """``check_alignment`` must surface a sentinel — not ``None`` — when
    LLM verification fails. ``None`` is reserved for "verified clean".
    """

    @pytest.mark.asyncio
    async def test_runtime_error_from_llm_yields_sentinel_tuple(
        self, orchestrator: AlignmentOrchestrator
    ) -> None:
        # Patch the inner LLM client so the orchestrator's per-step
        # try/except machinery is exercised (it wraps verify_alignment
        # with its own logging + raise pattern).
        ctx = _func_context("echo", line_number=4)

        async def _boom(_prompt: str, **_kwargs) -> str:
            # ``**_kwargs`` swallows the ``system_prompt`` kwarg the
            # orchestrator now forwards to ``verify_alignment``. Pre-fix
            # the LLM client only took ``prompt``; post-fix it also
            # accepts ``system_prompt`` so the framework template can
            # ride in the system role for Bedrock Anthropic.
            raise RuntimeError("simulated bedrock outage")

        # The prompt builder runs first; mock it out so the test only
        # exercises the LLM-call failure path. The orchestrator now
        # consumes the (system, user) split returned by
        # ``build_prompt_parts`` — the legacy single-string ``build_prompt``
        # is no longer in the orchestrator's call path.
        with patch.object(
            orchestrator.prompt_builder,
            "build_prompt_parts",
            return_value=("<system>", "<user>"),
        ), patch.object(
            orchestrator.llm_client,
            "verify_alignment",
            new=AsyncMock(side_effect=_boom),
        ):
            result = await orchestrator.check_alignment(ctx)

        assert result is not None, (
            "check_alignment must NOT return None when LLM verification "
            "fails — None is reserved for 'verified clean' and would "
            "let downstream collapse the failure into SAFE."
        )
        analysis, returned_ctx = result
        assert returned_ctx is ctx
        assert analysis.get(LLM_UNAVAILABLE_KEY) is True, (
            f"sentinel marker missing from analysis dict: {analysis}"
        )
        assert analysis.get("error_type") == "RuntimeError"
        assert "simulated bedrock outage" in analysis.get("error_message", "")
        # The skipped_error stat must increment so operators can see the
        # gap from get_statistics().
        assert orchestrator.stats["skipped_error"] >= 1

    @pytest.mark.asyncio
    async def test_clean_verification_still_returns_none(
        self, orchestrator: AlignmentOrchestrator
    ) -> None:
        """Negative control: when verification succeeds and finds no
        mismatch, ``check_alignment`` must still return ``None``. Only
        actual failures should yield the sentinel — a healthy LLM that
        says 'no mismatch' is the existing 'verified clean' signal.
        """
        ctx = _func_context("echo", line_number=4)
        with patch.object(
            orchestrator.prompt_builder,
            "build_prompt_parts",
            return_value=("<system>", "<user>"),
        ), patch.object(
            orchestrator.llm_client,
            "verify_alignment",
            new=AsyncMock(return_value="<llm-response>"),
        ), patch.object(
            orchestrator.response_validator,
            "validate",
            return_value={"mismatch_detected": False},
        ):
            result = await orchestrator.check_alignment(ctx)

        assert result is None, (
            f"verified-clean path must keep returning None, got {result!r}"
        )


class TestCheckAlignmentBatchEmitsSentinelOnFailure:
    """``check_alignment_batch`` must propagate sentinels for each
    function in a failed batch, instead of swallowing the exception.
    """

    @pytest.mark.asyncio
    async def test_whole_batch_failure_emits_one_sentinel_per_function(
        self, orchestrator: AlignmentOrchestrator
    ) -> None:
        contexts = [_func_context(f"tool_{i}", i + 1) for i in range(3)]

        async def _boom(_prompt: str, **_kwargs) -> str:
            raise RuntimeError("simulated llm outage")

        # Both the batched and the per-function fallback path must
        # observe the same LLM failure so we know the orchestrator
        # doesn't fall back into a different code path on the second
        # call. Patching ``verify_alignment`` covers both because
        # check_alignment also calls it during fallback.
        with patch.object(
            orchestrator.prompt_builder,
            "build_batch_prompt_parts",
            return_value=("<system>", "<batch-user>"),
        ), patch.object(
            orchestrator.prompt_builder,
            "build_prompt_parts",
            return_value=("<system>", "<single-user>"),
        ), patch.object(
            orchestrator.llm_client,
            "verify_alignment",
            new=AsyncMock(side_effect=_boom),
        ):
            results = await orchestrator.check_alignment_batch(contexts, batch_size=5)

        assert len(results) == len(contexts), (
            f"expected one sentinel per function, got {len(results)} for "
            f"{len(contexts)} input contexts"
        )
        for analysis, returned_ctx in results:
            assert analysis.get(LLM_UNAVAILABLE_KEY) is True, (
                f"every result tuple must carry the LLM_UNAVAILABLE_KEY "
                f"sentinel; got analysis={analysis}"
            )
            assert returned_ctx in contexts


class TestBehavioralCodeAnalyzerEmitsErrorNotSafe:
    """End-to-end regression: when the LLM provider is unreachable,
    ``BehavioralCodeAnalyzer.analyze`` must emit ``severity="ERROR"``
    rows for every scanned function and zero ``severity="SAFE"`` rows.
    This is the exact bug the user reported: the prior implementation
    silently emitted SAFE for every function on Bedrock validation
    failures, producing false-negative findings artifacts.
    """

    @pytest.mark.asyncio
    async def test_llm_unavailable_yields_error_findings_no_safe_rows(
        self,
    ) -> None:
        config = Config(llm_provider_api_key="test-key")
        analyzer = BehavioralCodeAnalyzer(config)

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False
        ) as f:
            f.write(_TWO_TOOL_MCP_SOURCE)
            f.flush()
            temp_path = f.name

        try:
            # Patch at the AlignmentLLMClient level so the test
            # exercises the full chain: orchestrator's batched call
            # raises -> per-function fallback also raises -> sentinels
            # propagate through check_alignment_batch -> code_analyzer's
            # _dispatch_finding routes them to _create_llm_unavailable_finding
            # -> SecurityFinding(severity="ERROR") emitted.
            async def _boom(_prompt: str, **_kwargs) -> str:
                raise RuntimeError(
                    "ValidationException: The provided model identifier "
                    "is invalid"
                )

            with patch.object(
                analyzer.alignment_orchestrator.llm_client,
                "verify_alignment",
                new=AsyncMock(side_effect=_boom),
            ):
                findings = await analyzer.analyze(
                    temp_path, {"file_path": temp_path}
                )
        finally:
            os.unlink(temp_path)

        assert isinstance(findings, list)
        assert all(isinstance(f, SecurityFinding) for f in findings)

        # The exact bug regression assertion: zero SAFE rows when the
        # LLM was unreachable. Previously this would have been 2.
        safe_findings = [f for f in findings if f.severity == "SAFE"]
        assert len(safe_findings) == 0, (
            "BehavioralCodeAnalyzer must NOT emit SAFE findings when "
            "the LLM provider is unreachable; SAFE means 'verified "
            "clean' and the LLM never returned a verdict. Got SAFE "
            f"findings: {[(f.summary, f.details) for f in safe_findings]}"
        )

        error_findings = [f for f in findings if f.severity == "ERROR"]
        assert len(error_findings) == 2, (
            "expected one ERROR finding per scanned tool (echo, add); "
            f"got {len(error_findings)}: "
            f"{[(f.severity, f.summary) for f in error_findings]}"
        )

        # Each ERROR row must be self-describing: function_name +
        # source_file + llm_unavailable=True so consumers can filter.
        names = sorted((f.details or {}).get("function_name") for f in error_findings)
        assert names == ["add", "echo"], names
        for f in error_findings:
            d = f.details or {}
            assert d.get("source_file") == temp_path
            assert d.get("llm_unavailable") is True, (
                "ERROR finding must mark details.llm_unavailable=True so "
                "consumers can distinguish LLM-availability errors from "
                "other future ERROR-severity sources"
            )
            assert d.get("error_type") == "RuntimeError"
            assert "ValidationException" in d.get("error_message", ""), (
                "the original Bedrock error message must survive into "
                "details.error_message so operators can debug without "
                "re-running with logging enabled"
            )
            # threat_category empty so ERROR rows don't pollute
            # downstream threat-name aggregates.
            assert f.threat_category == ""

    @pytest.mark.asyncio
    async def test_partial_llm_failure_does_not_corrupt_safe_rows_for_peers(
        self,
    ) -> None:
        """When the orchestrator returns a sentinel for one function and
        nothing for another (verified clean), the analyzer must emit
        exactly one ERROR row and one SAFE row — never an ERROR row that
        masquerades as SAFE for the unverified function.
        """
        config = Config(llm_provider_api_key="test-key")
        analyzer = BehavioralCodeAnalyzer(config)

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False
        ) as f:
            f.write(_TWO_TOOL_MCP_SOURCE)
            f.flush()
            temp_path = f.name

        try:
            captured_contexts: list = []

            async def _capture_then_partial(contexts, batch_size=5):
                # Mirror the new contract: return a sentinel for the
                # first function and nothing for the second (verified
                # clean). The first arg in tuple is the analysis dict.
                captured_contexts.extend(contexts)
                return [
                    (
                        {
                            LLM_UNAVAILABLE_KEY: True,
                            "mismatch_detected": False,
                            "error_type": "RuntimeError",
                            "error_message": "simulated outage",
                        },
                        contexts[0],
                    ),
                ]

            with patch.object(
                analyzer.alignment_orchestrator,
                "check_alignment_batch",
                new=AsyncMock(side_effect=_capture_then_partial),
            ):
                findings = await analyzer.analyze(
                    temp_path, {"file_path": temp_path}
                )
        finally:
            os.unlink(temp_path)

        assert len(captured_contexts) == 2, (
            "sanity: both tools should be sent through check_alignment_batch"
        )

        error_findings = [f for f in findings if f.severity == "ERROR"]
        safe_findings = [f for f in findings if f.severity == "SAFE"]

        assert len(error_findings) == 1, (
            f"expected exactly one ERROR finding (for the unverified "
            f"function); got {len(error_findings)}"
        )
        assert len(safe_findings) == 1, (
            f"expected exactly one SAFE finding (for the peer that the "
            f"LLM cleared); got {len(safe_findings)}"
        )

        # ERROR and SAFE must be for DIFFERENT functions. Otherwise
        # we'd have double-counted, which is itself a contract violation.
        error_func = (error_findings[0].details or {}).get("function_name")
        safe_func = (safe_findings[0].details or {}).get("function_name")
        assert error_func != safe_func, (
            f"ERROR and SAFE rows must cover disjoint functions; both "
            f"named {error_func}"
        )
