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

"""Regression tests for the empty-/garbage-response → silent-SAFE bug.

Background
----------
The orchestrator's pre-fix behaviour treated an "LLM responded but the
response was empty / ``{}`` / non-JSON / missing required fields" outcome
as identical to "verified clean" — both went through the ``return None``
branch in :meth:`AlignmentOrchestrator.check_alignment`. Combined with
``BehavioralCodeAnalyzer.analyze``'s synthesise-SAFE-for-everything-not-
returned policy, that meant Bedrock-hosted Anthropic models (which
consistently respond with ``{}`` to multi-KB prompts paired with
``response_format=json_object``) produced false-clean findings artifacts.

The fix adds :class:`AlignmentVerificationError` and routes validator
failures through it; the existing outer ``except Exception`` clause
converts them into the same ``LLM_UNAVAILABLE_KEY`` sentinel that
transport errors already produced. These tests lock the new contract:

1. Empty string response → sentinel.
2. ``{}`` response → sentinel.
3. Non-JSON response → sentinel.
4. Response missing required fields → sentinel.
5. Empty batch ``[]`` response → per-function fallback emits sentinels.
6. Batch item missing ``mismatch_detected`` → per-function fallback
   emits sentinels (no silent SAFE pad).
7. End-to-end: ``BehavioralCodeAnalyzer.analyze`` emits ERROR rows
   (not SAFE) when Bedrock hands back ``{}``.
"""

from __future__ import annotations

import os
import tempfile
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcpscanner.config import Config
from mcpscanner.core.analyzers.base import SecurityFinding
from mcpscanner.core.analyzers.behavioral.alignment.alignment_orchestrator import (
    LLM_UNAVAILABLE_KEY,
    AlignmentOrchestrator,
    AlignmentVerificationError,
)
from mcpscanner.core.analyzers.behavioral.alignment.alignment_response_validator import (
    AlignmentResponseValidator,
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
    """Build a minimal FunctionContext stub.

    Mirrors ``test_llm_unavailable_does_not_emit_safe.py``: only the
    fields the orchestrator touches for logging/finding construction
    need to be present.
    """
    fc = MagicMock()
    fc.name = name
    fc.line_number = line_number
    fc.decorator_types = ["mcp.tool"]
    return fc


@pytest.fixture
def orchestrator() -> AlignmentOrchestrator:
    """Orchestrator wired to a stub LLM client (real client is patched per-test)."""
    return AlignmentOrchestrator(Config(llm_provider_api_key="test-key"))


# ---------------------------------------------------------------------------
# AlignmentVerificationError exposure
# ---------------------------------------------------------------------------


class TestAlignmentVerificationErrorExposure:
    """Ensure the new exception type is publicly importable.

    Downstream code (e.g. integration test harnesses, CLI scripts) may
    want to catch it specifically — guarding against re-renames.
    """

    def test_exception_is_a_runtimeerror(self) -> None:
        assert issubclass(AlignmentVerificationError, RuntimeError)


# ---------------------------------------------------------------------------
# check_alignment: each validator-failure flavour → sentinel
# ---------------------------------------------------------------------------


class TestCheckAlignmentValidatorFailuresEmitSentinel:
    """Each shape of "LLM responded with garbage" must yield the
    ``LLM_UNAVAILABLE_KEY`` sentinel — not ``None``.
    """

    @pytest.mark.parametrize(
        "raw_response,case_label",
        [
            ("", "empty_string"),
            ("   \n\t  ", "whitespace_only"),
            ("{}", "empty_json_object"),
            ("not json at all", "non_json"),
            ("[]", "json_array_not_dict"),
            ('{"foo": "bar"}', "missing_mismatch_detected"),
            (
                # mismatch_detected=true but missing the threat_name /
                # summary required-on-mismatch fields — the validator
                # rejects this shape, and the orchestrator must NOT
                # silently treat it as clean.
                '{"mismatch_detected": true}',
                "mismatch_with_missing_required_fields",
            ),
        ],
    )
    @pytest.mark.asyncio
    async def test_garbage_response_yields_sentinel_tuple(
        self,
        orchestrator: AlignmentOrchestrator,
        raw_response: str,
        case_label: str,
    ) -> None:
        ctx = _func_context(f"tool_{case_label}", line_number=10)

        with patch.object(
            orchestrator.prompt_builder,
            "build_prompt_parts",
            return_value=("<system>", "<user>"),
        ), patch.object(
            orchestrator.llm_client,
            "verify_alignment",
            new=AsyncMock(return_value=raw_response),
        ):
            result = await orchestrator.check_alignment(ctx)

        assert result is not None, (
            f"check_alignment must NOT return None for {case_label!r} — "
            f"None is reserved for verified-clean. Returning None on a "
            f"validator failure is exactly the silent-SAFE bug we are "
            f"regressing against."
        )
        analysis, returned_ctx = result
        assert returned_ctx is ctx
        assert analysis.get(LLM_UNAVAILABLE_KEY) is True, (
            f"sentinel marker missing for {case_label!r}: {analysis!r}"
        )
        assert analysis.get("error_type") == "AlignmentVerificationError", (
            f"sentinel must carry the AlignmentVerificationError type so "
            f"operators can distinguish validator failures from transport "
            f"failures (RuntimeError, etc.); got "
            f"error_type={analysis.get('error_type')!r}"
        )
        # Stat plumbing: validator failures bump skipped_invalid_response
        # AND are surfaced as sentinels. Both signals matter — the stat
        # is what shows up in get_statistics() summaries, the sentinel
        # is what shows up in the findings artefact.
        assert orchestrator.stats["skipped_invalid_response"] >= 1
        assert orchestrator.stats["skipped_error"] >= 1


# ---------------------------------------------------------------------------
# check_alignment_batch: the various ways a batch response can fail
# ---------------------------------------------------------------------------


class TestCheckAlignmentBatchFallsBackOnGarbageResponses:
    """When the batch response is garbage the orchestrator must fall
    back to per-function ``check_alignment`` calls — and each of those
    must emit a sentinel (because the second-pass response is garbage
    too in these scenarios). The net effect: one sentinel per function,
    zero silently-padded SAFE rows.
    """

    @pytest.mark.parametrize(
        "raw_response,case_label",
        [
            ("[]", "empty_array"),
            ('[{"mismatch_detected": false}]', "truncated_array"),
            ('[{"foo": 1}, {"foo": 2}]', "items_missing_mismatch_detected"),
            ('[{"mismatch_detected": false}, "not a dict"]', "non_dict_item"),
        ],
    )
    @pytest.mark.asyncio
    async def test_batch_garbage_falls_back_to_sentinels(
        self,
        orchestrator: AlignmentOrchestrator,
        raw_response: str,
        case_label: str,
    ) -> None:
        contexts = [_func_context(f"tool_{i}", i + 1) for i in range(2)]

        # The same garbage response is returned for both the batched
        # call and any per-function fallback call (the LLM client is
        # patched once and reused). For ``empty_array`` /
        # ``truncated_array`` the per-function fallback hits the
        # single-function validator, which rejects ``[]`` (not a dict)
        # → sentinel. For ``items_missing_mismatch_detected`` the
        # single-function validator also rejects the array shape →
        # sentinel.
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
            new=AsyncMock(return_value=raw_response),
        ):
            results = await orchestrator.check_alignment_batch(
                contexts, batch_size=5
            )

        assert len(results) == len(contexts), (
            f"{case_label}: expected one sentinel per function, got "
            f"{len(results)} results for {len(contexts)} input contexts"
        )
        for analysis, returned_ctx in results:
            assert analysis.get(LLM_UNAVAILABLE_KEY) is True, (
                f"{case_label}: every result must carry the sentinel; "
                f"got analysis={analysis!r}"
            )
            assert returned_ctx in contexts


# ---------------------------------------------------------------------------
# AlignmentResponseValidator: direct unit tests for the new batch policy
# ---------------------------------------------------------------------------


class TestValidateBatchNoSilentPadding:
    """The batch validator used to silently pad missing
    ``mismatch_detected`` items with ``False`` — collapsing
    "couldn't verify" into "verified clean". Lock the new
    return-None-on-ambiguity policy.
    """

    def test_empty_array_returns_none(self) -> None:
        validator = AlignmentResponseValidator()
        assert validator.validate_batch("[]", expected_count=3) is None

    def test_truncated_array_returns_none(self) -> None:
        validator = AlignmentResponseValidator()
        # 2 items returned but 3 expected — must fall back, not pad.
        response = (
            '[{"mismatch_detected": false},'
            ' {"mismatch_detected": false}]'
        )
        assert validator.validate_batch(response, expected_count=3) is None

    def test_item_missing_mismatch_detected_returns_none(self) -> None:
        validator = AlignmentResponseValidator()
        response = (
            '[{"mismatch_detected": false},'
            ' {"function_name": "x"}]'
        )
        assert validator.validate_batch(response, expected_count=2) is None

    def test_non_dict_item_returns_none(self) -> None:
        validator = AlignmentResponseValidator()
        response = '[{"mismatch_detected": false}, "garbage"]'
        assert validator.validate_batch(response, expected_count=2) is None

    def test_well_formed_batch_still_validates(self) -> None:
        """Negative control: a healthy batch response must still pass."""
        validator = AlignmentResponseValidator()
        response = (
            '[{"mismatch_detected": false},'
            ' {"mismatch_detected": true,'
            '   "threat_name": "DATA EXFILTRATION",'
            '   "summary": "leaks input"}]'
        )
        results = validator.validate_batch(response, expected_count=2)
        assert results is not None
        assert len(results) == 2
        assert results[0]["mismatch_detected"] is False
        assert results[1]["mismatch_detected"] is True


# ---------------------------------------------------------------------------
# End-to-end: BehavioralCodeAnalyzer must emit ERROR (not SAFE) for {}
# ---------------------------------------------------------------------------


class TestBehavioralCodeAnalyzerEmitsErrorOnEmptyJsonResponse:
    """End-to-end regression for the exact Bedrock-Anthropic failure
    mode the user encountered: model responds with ``{}`` to every
    function in the batch, ``BehavioralCodeAnalyzer.analyze`` must emit
    ``severity="ERROR"`` rows (not SAFE) for each function.
    """

    @pytest.mark.asyncio
    async def test_empty_json_response_yields_error_findings_no_safe_rows(
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
            # Simulate the exact bug: every LLM call returns "{}".
            # Pre-fix: orchestrator silently swallowed → analyzer
            # synthesised SAFE for both tools. Post-fix: orchestrator
            # raises AlignmentVerificationError → outer except emits
            # sentinel → analyzer emits ERROR.
            async def _empty(*_args, **_kwargs) -> str:
                return "{}"

            with patch.object(
                analyzer.alignment_orchestrator.llm_client,
                "verify_alignment",
                new=AsyncMock(side_effect=_empty),
            ):
                findings = await analyzer.analyze(
                    temp_path, {"file_path": temp_path}
                )
        finally:
            os.unlink(temp_path)

        assert isinstance(findings, list)
        assert all(isinstance(f, SecurityFinding) for f in findings)

        safe_findings = [f for f in findings if f.severity == "SAFE"]
        assert len(safe_findings) == 0, (
            "BehavioralCodeAnalyzer must NOT emit SAFE findings when "
            "the LLM returned empty {} for every function — that was "
            "the exact silent-SAFE bug we are regressing against. Got "
            f"SAFE findings: {[(f.summary, f.details) for f in safe_findings]}"
        )

        error_findings = [f for f in findings if f.severity == "ERROR"]
        assert len(error_findings) == 2, (
            "expected one ERROR finding per scanned tool (echo, add); "
            f"got {len(error_findings)}: "
            f"{[(f.severity, f.summary) for f in error_findings]}"
        )

        for f in error_findings:
            d = f.details or {}
            assert d.get("llm_unavailable") is True
            assert d.get("error_type") == "AlignmentVerificationError", (
                "ERROR rows from validator-failures must carry "
                "error_type=AlignmentVerificationError so operators can "
                "distinguish 'LLM said {}' from 'LLM was unreachable'; "
                f"got {d.get('error_type')!r}"
            )


# ---------------------------------------------------------------------------
# AlignmentLLMClient: response_format and message-shape regressions
# ---------------------------------------------------------------------------


class TestLLMClientMessageShape:
    """The Bedrock-friendly fix moved the 73 KB framework template from
    the user role to the system role. Lock that:

    1. ``system_prompt`` kwarg is concatenated after the built-in
       ``_BASE_SYSTEM_PREAMBLE`` and lands in role=system.
    2. The user role contains ONLY the per-call payload (i.e. the
       prompt builder's ``user_payload`` half), not the template.
    3. ``response_format=json_object`` is set for openai/azure models
       and OMITTED for bedrock/anthropic/cohere. This is the second
       half of the Bedrock fix — the json_object flag is what made
       Bedrock Anthropic short-circuit even after we split the prompt.
    """

    @pytest.mark.asyncio
    async def test_system_prompt_kwarg_lands_in_system_role(self) -> None:
        from mcpscanner.core.analyzers.behavioral.alignment.alignment_llm_client import (
            AlignmentLLMClient,
        )

        client = AlignmentLLMClient(Config(llm_provider_api_key="test-key"))
        captured: dict = {}

        async def _capture(**kwargs):
            captured.update(kwargs)
            mock_response = MagicMock()
            mock_response.choices = [MagicMock()]
            mock_response.choices[0].message.content = (
                '{"mismatch_detected": false}'
            )
            return mock_response

        with patch(
            "mcpscanner.core.analyzers.behavioral.alignment."
            "alignment_llm_client.acompletion",
            new=AsyncMock(side_effect=_capture),
        ):
            await client.verify_alignment(
                "<user-only-payload>", system_prompt="<framework-template>"
            )

        messages = captured["messages"]
        assert len(messages) == 2
        assert messages[0]["role"] == "system"
        assert messages[1]["role"] == "user"
        # The framework-template kwarg must show up in the system slot,
        # NOT the user slot. This is the whole point of the fix.
        assert "<framework-template>" in messages[0]["content"]
        assert "<framework-template>" not in messages[1]["content"]
        # The user slot should contain ONLY the per-call payload.
        assert messages[1]["content"] == "<user-only-payload>"

    @pytest.mark.asyncio
    async def test_response_format_omitted_for_bedrock(self) -> None:
        """Bedrock Anthropic returns ``{}`` when paired with
        ``response_format=json_object`` and a multi-KB prompt — the
        flag is the trigger. Make sure we never set it for bedrock
        model ids.
        """
        from mcpscanner.core.analyzers.behavioral.alignment.alignment_llm_client import (
            AlignmentLLMClient,
        )

        config = Config(
            llm_provider_api_key=None,
            llm_model="bedrock/anthropic.claude-haiku-4-5-20251001-v1:0",
            aws_region_name="us-west-2",
        )
        client = AlignmentLLMClient(config)
        captured: dict = {}

        async def _capture(**kwargs):
            captured.update(kwargs)
            mock_response = MagicMock()
            mock_response.choices = [MagicMock()]
            mock_response.choices[0].message.content = (
                '{"mismatch_detected": false}'
            )
            return mock_response

        with patch(
            "mcpscanner.core.analyzers.behavioral.alignment."
            "alignment_llm_client.acompletion",
            new=AsyncMock(side_effect=_capture),
        ):
            await client.verify_alignment("<user>", system_prompt="<sys>")

        assert "response_format" not in captured, (
            "Bedrock requests must NOT carry response_format=json_object — "
            "that flag is what makes Bedrock Anthropic respond with {} on "
            "long prompts. Got captured kwargs: "
            f"{sorted(captured.keys())}"
        )

    @pytest.mark.asyncio
    async def test_response_format_set_for_openai(self) -> None:
        """Negative control: native JSON mode must still be enabled for
        the providers that handle it correctly (OpenAI, Azure-OpenAI).
        """
        from mcpscanner.core.analyzers.behavioral.alignment.alignment_llm_client import (
            AlignmentLLMClient,
        )

        config = Config(
            llm_provider_api_key="test-key",
            llm_model="gpt-4o",
        )
        client = AlignmentLLMClient(config)
        captured: dict = {}

        async def _capture(**kwargs):
            captured.update(kwargs)
            mock_response = MagicMock()
            mock_response.choices = [MagicMock()]
            mock_response.choices[0].message.content = (
                '{"mismatch_detected": false}'
            )
            return mock_response

        with patch(
            "mcpscanner.core.analyzers.behavioral.alignment."
            "alignment_llm_client.acompletion",
            new=AsyncMock(side_effect=_capture),
        ):
            await client.verify_alignment("<user>", system_prompt="<sys>")

        assert captured.get("response_format") == {"type": "json_object"}, (
            "OpenAI/Azure should keep getting response_format=json_object — "
            "that's where the fix is allowed to use the native flag. Got: "
            f"response_format={captured.get('response_format')!r}"
        )
