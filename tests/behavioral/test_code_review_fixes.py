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

"""Regression tests for the post-review fixes across the alignment stack."""

from __future__ import annotations

import logging
from types import SimpleNamespace

import pytest

from mcpscanner.config.config import Config
from mcpscanner.core.analyzers.behavioral.alignment.alignment_llm_client import (
    _classify_provider,
)
from mcpscanner.core.analyzers.behavioral.alignment.alignment_orchestrator import (
    AlignmentOrchestrator,
)
from mcpscanner.core.analyzers.behavioral.alignment.alignment_response_validator import (
    _UNANALYSED_KEY,
    AlignmentResponseValidator,
    is_unanalysed,
)
from mcpscanner.core.analyzers.behavioral.code_analyzer import BehavioralCodeAnalyzer
from mcpscanner.utils.log_format import sanitize_log_value


def _cfg() -> Config:
    return Config(llm_model="gpt-4o", llm_provider_api_key="sk-test")


def _ctx(name: str = "foo") -> SimpleNamespace:
    return SimpleNamespace(name=name)


# ---------------------------------------------------------------------------
# P0.1 — skipped_error must NOT double-count failures
# ---------------------------------------------------------------------------


class TestSkippedErrorNotDoubleCounted:
    """``check_alignment`` failure paths must increment ``skipped_error`` once."""

    @pytest.mark.asyncio
    async def test_prompt_build_failure_counts_once(self, monkeypatch):
        orch = AlignmentOrchestrator(_cfg())

        class _Boom:
            def build_prompt(self, ctx):
                raise RuntimeError("prompt boom")

        orch.prompt_builder = _Boom()
        await orch.check_alignment(_ctx("a"))
        assert orch.stats["skipped_error"] == 1
        assert "a" in orch.errored_function_names

    @pytest.mark.asyncio
    async def test_llm_failure_counts_once(self, monkeypatch):
        orch = AlignmentOrchestrator(_cfg())
        orch.prompt_builder = SimpleNamespace(build_prompt=lambda _c: "p")

        async def _kaboom(_p):
            raise RuntimeError("llm boom")

        orch.llm_client = SimpleNamespace(verify_alignment=_kaboom)
        await orch.check_alignment(_ctx("b"))
        assert orch.stats["skipped_error"] == 1
        assert "b" in orch.errored_function_names

    @pytest.mark.asyncio
    async def test_validator_failure_counts_once(self, monkeypatch):
        orch = AlignmentOrchestrator(_cfg())
        orch.prompt_builder = SimpleNamespace(build_prompt=lambda _c: "p")

        async def _ok(_p):
            return "{}"

        orch.llm_client = SimpleNamespace(verify_alignment=_ok)
        orch.response_validator = SimpleNamespace(
            validate=lambda _r: (_ for _ in ()).throw(RuntimeError("validator boom"))
        )
        await orch.check_alignment(_ctx("c"))
        assert orch.stats["skipped_error"] == 1


# ---------------------------------------------------------------------------
# P0.2 — validate_batch JSONDecodeError path must validate items
# ---------------------------------------------------------------------------


class TestValidateBatchMarkdownFallbackValidatesItems:
    """The markdown-fallback path must apply the same validation + padding."""

    def test_non_dict_item_replaced_with_default(self):
        v = AlignmentResponseValidator()
        # Item 0 claims a mismatch but lacks ``threat_name``/``summary``
        # — that's a malformed dict and must be tagged unanalysed.
        # Items 1 and 2 are not dicts. Slots 3 & 4 are short-padded.
        resp = (
            "preamble ```json\n"
            '[{"mismatch_detected": true}, 42, "string-not-dict"]\n'
            "``` trailing"
        )
        out = v.validate_batch(resp, expected_count=5)
        assert out is not None and len(out) == 5
        assert all(isinstance(item, dict) for item in out)
        for idx in range(5):
            assert out[idx]["mismatch_detected"] is False, (
                f"slot {idx} should be coerced to False, got {out[idx]!r}"
            )
            assert out[idx].get(_UNANALYSED_KEY) is True, (
                f"slot {idx} should be tagged unanalysed, got {out[idx]!r}"
            )

    def test_well_formed_mismatch_passes_through(self):
        v = AlignmentResponseValidator()
        resp = (
            '```json\n['
            '{"mismatch_detected": true, "threat_name": "T", "summary": "s"},'
            '{"mismatch_detected": false}'
            ']\n```'
        )
        out = v.validate_batch(resp, expected_count=2)
        assert out is not None and len(out) == 2
        # Well-formed mismatch: passes through untouched.
        assert out[0]["mismatch_detected"] is True
        assert out[0].get(_UNANALYSED_KEY) is not True
        # Well-formed clean: passes through untouched.
        assert out[1]["mismatch_detected"] is False
        assert out[1].get(_UNANALYSED_KEY) is not True

    def test_dict_missing_mismatch_detected_routed_to_errored(self):
        v = AlignmentResponseValidator()
        resp = '```json\n[{"foo": 1}, {"mismatch_detected": false}]\n```'
        out = v.validate_batch(resp, expected_count=2)
        assert out is not None and len(out) == 2
        # The first item has no ``mismatch_detected`` field at all
        # → unanalysed sentinel.
        assert out[0]["mismatch_detected"] is False
        assert out[0].get(_UNANALYSED_KEY) is True
        # The second item is well-formed clean.
        assert out[1]["mismatch_detected"] is False
        assert out[1].get(_UNANALYSED_KEY) is not True


# ---------------------------------------------------------------------------
# P0.3 — analyze() error path must NOT raise UnboundLocalError
# ---------------------------------------------------------------------------


class TestAnalyzeUnboundScanModeRegression:
    """``analyze`` must remain total when reset_stats raises."""

    @pytest.mark.asyncio
    async def test_reset_stats_raises_returns_empty(self, caplog, monkeypatch):
        from mcpscanner.utils.logging_config import get_logger

        analyzer = BehavioralCodeAnalyzer(_cfg())

        def _boom():
            raise RuntimeError("reset_stats boom")

        analyzer.alignment_orchestrator.reset_stats = _boom  # type: ignore[method-assign]

        # The behavioural logger uses ``propagate=False`` so root-level
        # caplog can't see it. Flip propagation for the test.
        behavioral_logger = get_logger("mcpscanner.core.analyzers.base.Behavioural")
        monkeypatch.setattr(behavioral_logger, "propagate", True)

        with caplog.at_level(logging.ERROR):
            result = await analyzer.analyze("/nonexistent/path", {"tool_name": "t"})

        assert result == []
        # The error handler logged the failure with the pre-initialised
        # sentinel values (``mode=unknown target=-``), confirming neither
        # variable was unbound.
        failed = [
            r.getMessage() for r in caplog.records
            if r.getMessage().startswith("behavioral scan failed")
        ]
        assert failed, f"expected a 'behavioral scan failed' line in {caplog.text!r}"
        line = failed[0]
        assert "mode=unknown" in line
        assert "target=-" in line


# ---------------------------------------------------------------------------
# P1.2 — sanitize_log_value preserves numeric falsy values
# ---------------------------------------------------------------------------


class TestSanitizeLogValueFalsy:
    def test_none_collapses_to_dash(self):
        assert sanitize_log_value(None) == "-"

    def test_empty_string_collapses_to_dash(self):
        assert sanitize_log_value("") == "-"

    def test_zero_is_rendered_verbatim(self):
        assert sanitize_log_value(0) == "0"

    def test_false_is_rendered_verbatim(self):
        assert sanitize_log_value(False) == "False"



# ---------------------------------------------------------------------------
# P2.1 — errored functions get ERROR severity, not SAFE
# ---------------------------------------------------------------------------


class TestErroredFunctionSurfacedAsError:
    """A function whose alignment check errored must be surfaced as ERROR."""

    @pytest.mark.asyncio
    async def test_errored_function_synthesised_as_error_not_safe(
        self, tmp_path, monkeypatch
    ):
        analyzer = BehavioralCodeAnalyzer(_cfg())

        # A single function takes the non-batched path inside
        # ``_analyze_source_code``; stub just ``check_alignment``.
        async def _stub_check_alignment(func_context):
            analyzer.alignment_orchestrator.errored_function_names.add(
                func_context.name
            )
            return None

        monkeypatch.setattr(
            analyzer.alignment_orchestrator,
            "check_alignment",
            _stub_check_alignment,
        )

        py_source = (
            "from mcp.server.fastmcp import FastMCP\n"
            'mcp = FastMCP("test")\n'
            "@mcp.tool()\n"
            "def captured_tool(x: str) -> str:\n"
            '    """Docstring."""\n'
            "    return x\n"
        )
        py = tmp_path / "tool.py"
        py.write_text(py_source)

        findings = await analyzer.analyze(
            str(py),
            {"tool_name": "captured_tool", "file_path": str(py)},
        )

        my = [
            f for f in findings
            if (f.details or {}).get("function_name") == "captured_tool"
        ]
        assert len(my) == 1, f"expected one finding, got {findings!r}"
        assert my[0].severity == "UNKNOWN"
        assert (my[0].details or {}).get("analysis_status") == "errored"


# ---------------------------------------------------------------------------
# Batch-failure regression coverage (post-review)
# ---------------------------------------------------------------------------


class TestBatchFallbackCleanRetryNotFlaggedErrored:
    """If the batch path fails wholesale, cleanly-retried functions must
    NOT end up in ``errored_function_names``."""

    @pytest.mark.asyncio
    async def test_clean_retries_do_not_pollute_errored_set(self, monkeypatch):
        orch = AlignmentOrchestrator(_cfg())

        def _build_batch(_b):
            raise RuntimeError("batch boom")

        orch.prompt_builder = SimpleNamespace(
            build_batch_prompt=_build_batch,
            build_prompt=lambda _c: "p",
        )

        async def _verify(_p):
            return '{"mismatch_detected": false}'

        orch.llm_client = SimpleNamespace(verify_alignment=_verify)
        orch.response_validator.validate = lambda r: {"mismatch_detected": False}

        ctxs = [SimpleNamespace(name="clean1"), SimpleNamespace(name="clean2")]
        results = await orch.check_alignment_batch(ctxs, batch_size=2)

        assert results == []
        assert orch.errored_function_names == set(), (
            f"clean retries should not be marked errored, got "
            f"{orch.errored_function_names!r}"
        )
        assert orch.stats["no_mismatch"] == 2
        assert orch.stats["skipped_error"] == 0

    @pytest.mark.asyncio
    async def test_real_retry_errors_still_marked(self, monkeypatch):
        """When the *retried* per-function check actually raises, the
        function must be marked errored (so the SAFE-synth loop can
        promote it to UNKNOWN).

        Note: this test implicitly pins ``check_alignment``'s
        no-re-raise contract — its outer ``except`` returns ``None``
        rather than propagating. If that contract ever changes, the
        ``check_alignment_batch`` retry loop will crash and this test
        will be the canary.
        """
        orch = AlignmentOrchestrator(_cfg())

        def _build_batch(_b):
            raise RuntimeError("batch boom")

        def _build_one(_c):
            raise RuntimeError("per-fn boom")

        orch.prompt_builder = SimpleNamespace(
            build_batch_prompt=_build_batch,
            build_prompt=_build_one,
        )

        ctxs = [SimpleNamespace(name="errfn")]
        # No ``pytest.raises`` — the batch entry point must absorb both
        # the batch-level and per-fn exceptions.
        results = await orch.check_alignment_batch(ctxs, batch_size=1)

        assert results == []
        assert "errfn" in orch.errored_function_names
        assert orch.stats["skipped_error"] == 1


class TestBatchPaddingRoutesToErrored:
    """Padded/malformed batch slots must route to ``errored_function_names``
    and be surfaced as UNKNOWN."""

    def test_validator_tags_padded_slots(self):
        v = AlignmentResponseValidator()
        # LLM returned 1 item; we asked for 3.
        out = v.validate_batch('[{"mismatch_detected": false}]', expected_count=3)
        assert out is not None and len(out) == 3
        assert out[0].get(_UNANALYSED_KEY) is not True
        assert out[1].get(_UNANALYSED_KEY) is True
        assert out[2].get(_UNANALYSED_KEY) is True

    def test_validator_routes_mismatch_missing_fields_to_unanalysed(self):
        v = AlignmentResponseValidator()
        out = v.validate_batch(
            '[{"mismatch_detected": true}]', expected_count=1
        )
        assert out is not None and len(out) == 1
        assert out[0][_UNANALYSED_KEY] is True
        assert out[0]["mismatch_detected"] is False

    @pytest.mark.asyncio
    async def test_orchestrator_routes_unanalysed_to_errored_set(self, monkeypatch):
        orch = AlignmentOrchestrator(_cfg())

        orch.prompt_builder = SimpleNamespace(
            build_batch_prompt=lambda _b: "p",
            build_prompt=lambda _c: "p",
        )

        async def _verify(_p):
            return '[{"mismatch_detected": false}]'  # only 1 of 3

        orch.llm_client = SimpleNamespace(verify_alignment=_verify)

        ctxs = [
            SimpleNamespace(name="real_clean"),
            SimpleNamespace(name="padded_a"),
            SimpleNamespace(name="padded_b"),
        ]
        results = await orch.check_alignment_batch(ctxs, batch_size=3)

        assert results == []
        assert orch.errored_function_names == {"padded_a", "padded_b"}
        # Unanalysed slots count toward skipped_invalid_response.
        assert orch.stats["no_mismatch"] == 1
        assert orch.stats["skipped_invalid_response"] == 2


class TestValidatorStripsAdversarialSentinel:
    """An LLM-supplied ``_unanalysed`` key must never survive on a
    passthrough result — otherwise an adversarial model could coerce
    its own clean responses into the errored bucket."""

    def test_clean_with_llm_supplied_sentinel_is_stripped(self):
        v = AlignmentResponseValidator()
        resp = '[{"mismatch_detected": false, "%s": true}]' % _UNANALYSED_KEY
        out = v.validate_batch(resp, expected_count=1)
        assert out is not None and len(out) == 1
        assert out[0]["mismatch_detected"] is False
        assert _UNANALYSED_KEY not in out[0], (
            "validator must strip adversarial sentinel from LLM-supplied dicts"
        )

    def test_mismatch_with_llm_supplied_sentinel_is_stripped(self):
        v = AlignmentResponseValidator()
        resp = (
            '[{"mismatch_detected": true, "threat_name": "T", '
            '"summary": "s", "%s": true}]' % _UNANALYSED_KEY
        )
        out = v.validate_batch(resp, expected_count=1)
        assert out is not None and len(out) == 1
        assert out[0]["mismatch_detected"] is True
        assert _UNANALYSED_KEY not in out[0]

    @pytest.mark.asyncio
    async def test_orchestrator_treats_stripped_dict_as_clean(self, monkeypatch):
        orch = AlignmentOrchestrator(_cfg())
        orch.prompt_builder = SimpleNamespace(
            build_batch_prompt=lambda _b: "p",
            build_prompt=lambda _c: "p",
        )

        async def _verify(_p):
            return (
                '[{"mismatch_detected": false, "%s": true}]' % _UNANALYSED_KEY
            )

        orch.llm_client = SimpleNamespace(verify_alignment=_verify)

        ctxs = [SimpleNamespace(name="target")]
        results = await orch.check_alignment_batch(ctxs, batch_size=1)

        assert results == []
        # The adversarial sentinel was stripped, so the function is
        # counted as clean — NOT routed to errored.
        assert "target" not in orch.errored_function_names
        assert orch.stats["no_mismatch"] == 1
        assert orch.stats["skipped_invalid_response"] == 0


class TestStatsPartitioningInvariant:
    """``total_analyzed`` must equal the sum of the four outcome buckets.

    This is the contract documented on ``AlignmentOrchestrator.get_statistics``.
    """

    @pytest.mark.asyncio
    async def test_invariant_holds_for_mixed_batch(self, monkeypatch):
        orch = AlignmentOrchestrator(_cfg())
        orch.prompt_builder = SimpleNamespace(
            build_batch_prompt=lambda _b: "p",
            build_prompt=lambda _c: "p",
        )

        # 1 well-formed mismatch + 1 well-formed clean + 1 short-padded.
        async def _verify(_p):
            return (
                '[{"mismatch_detected": true, "threat_name": "T", "summary": "s"},'
                ' {"mismatch_detected": false}]'
            )

        orch.llm_client = SimpleNamespace(verify_alignment=_verify)

        # Bypass the threat-vuln classifier (it needs a real LLM client).
        # Must be ``async`` because the orchestrator awaits it.
        async def _classify_none(**_kw):
            return None

        orch.threat_vuln_classifier = SimpleNamespace(
            classify_finding=_classify_none
        )

        ctxs = [
            SimpleNamespace(name="bad"),
            SimpleNamespace(name="good"),
            SimpleNamespace(name="short_padded"),
        ]
        await orch.check_alignment_batch(ctxs, batch_size=3)

        s = orch.stats
        assert s["total_analyzed"] == (
            s["mismatches_detected"]
            + s["no_mismatch"]
            + s["skipped_invalid_response"]
            + s["skipped_error"]
        ), f"invariant violated: {s}"
        assert s["mismatches_detected"] == 1
        assert s["no_mismatch"] == 1
        assert s["skipped_invalid_response"] == 1
        assert s["skipped_error"] == 0
        assert s["total_analyzed"] == 3

    @pytest.mark.asyncio
    async def test_invariant_holds_when_validate_batch_returns_none(
        self, monkeypatch
    ):
        """``validate_batch`` returning ``None`` (hard failure) must hit
        the per-function fallback and still leave the invariant intact."""
        orch = AlignmentOrchestrator(_cfg())
        orch.prompt_builder = SimpleNamespace(
            build_batch_prompt=lambda _b: "p",
            build_prompt=lambda _c: "p",
        )

        async def _verify(_p):
            return ""  # → validate_batch returns None → fallback

        orch.llm_client = SimpleNamespace(verify_alignment=_verify)
        # The fallback per-function check_alignment will call validate("")
        # → validator returns None → orchestrator increments
        # skipped_invalid_response. We don't intercept it.

        ctxs = [SimpleNamespace(name="a"), SimpleNamespace(name="b")]
        await orch.check_alignment_batch(ctxs, batch_size=2)

        s = orch.stats
        assert s["total_analyzed"] == (
            s["mismatches_detected"]
            + s["no_mismatch"]
            + s["skipped_invalid_response"]
            + s["skipped_error"]
        ), f"invariant violated after fallback: {s}"
        # Both functions were attempted, both hit the invalid-response path.
        assert s["skipped_invalid_response"] == 2
        assert {"a", "b"} <= orch.errored_function_names


class TestMarkdownExtractorFenceHandling:
    """``_extract_json_array_from_markdown`` must handle truncated /
    missing fences without silently dropping characters."""

    def test_missing_closing_fence_slices_to_end(self):
        v = AlignmentResponseValidator()
        # No closing fence — the extractor should still try and parse.
        resp = '```json\n[{"mismatch_detected": false}]'
        out = v._extract_json_array_from_markdown(resp)
        assert out == [{"mismatch_detected": False}]

    def test_no_fence_returns_none(self):
        v = AlignmentResponseValidator()
        assert v._extract_json_array_from_markdown("no fence at all") is None


class TestAnalyzedFunctionsResetOnEarlyFailure:
    """If ``reset_stats`` raises before ``_analyze_source_code`` runs, the
    next caller must not see stale ``analyzed_functions`` from the
    previous scan."""

    @pytest.mark.asyncio
    async def test_analyzed_functions_cleared_even_when_reset_stats_raises(
        self, monkeypatch
    ):
        analyzer = BehavioralCodeAnalyzer(_cfg())
        analyzer.analyzed_functions = [{"name": "stale_from_prev_scan"}]

        def _boom():
            raise RuntimeError("reset_stats boom")

        analyzer.alignment_orchestrator.reset_stats = _boom  # type: ignore[method-assign]

        result = await analyzer.analyze("/nonexistent", {"tool_name": "t"})
        assert result == []
        assert analyzer.analyzed_functions == [], (
            "stale analyzed_functions should be cleared even when the "
            "scan body bails before populating it"
        )


# ---------------------------------------------------------------------------
# P2.2 — provider classifier handles split-on-slash and bare GPT
# ---------------------------------------------------------------------------


class TestProviderClassifier:
    @pytest.mark.parametrize(
        "model,expected",
        [
            ("bedrock/anthropic.claude-3-haiku-20240307-v1:0", "bedrock"),
            ("azure/gpt-4o", "azure"),
            ("openai/gpt-4o", "openai"),
            ("anthropic/claude-3-5-sonnet-20240620", "anthropic"),
            ("gemini/gemini-1.5-pro-latest", "google"),
            ("vertex_ai/gemini-1.5-pro", "google"),
            ("cohere/command-r-plus", "cohere"),
            ("mistral/mistral-large-latest", "mistral"),
            ("groq/llama3-70b-8192", "groq"),
            # Bare GPT
            ("gpt-4o", "openai"),
            ("o1-preview", "openai"),
            ("o3-mini", "openai"),
            ("chatgpt-4o-latest", "openai"),
            # Unknown
            ("", "unknown"),
            ("random-unbranded-model", "other"),
            # Unknown provider prefix is echoed back, NOT misclassified.
            ("future-provider/llama-9000", "future-provider"),
        ],
    )
    def test_classify(self, model, expected):
        assert _classify_provider(model) == expected


# ---------------------------------------------------------------------------
# Post-review P2.1 — single-shot validate() must also strip adversarial
# ``_unanalysed`` keys, not just the batch path.
# ---------------------------------------------------------------------------


class TestSingleShotValidateStripsSentinel:
    """``validate()`` and ``validate_batch()`` share the same sentinel
    contract: the LLM must not be able to inject ``_unanalysed`` via
    either entrypoint. The batch path was covered first; this pins the
    single-shot path."""

    def test_single_shot_clean_strips_llm_supplied_sentinel(self, caplog):
        v = AlignmentResponseValidator()
        resp = (
            '{"mismatch_detected": false, "%s": true, "extra": "x"}'
            % _UNANALYSED_KEY
        )
        with caplog.at_level(
            logging.WARNING,
            logger=(
                "mcpscanner.core.analyzers.behavioral.alignment."
                "alignment_response_validator"
            ),
        ):
            out = v.validate(resp)

        assert out is not None
        assert _UNANALYSED_KEY not in out, (
            "validate() must strip adversarial sentinel from single-shot "
            "result; otherwise an attacker-controlled response coerces "
            "downstream into the errored bucket"
        )
        assert out["mismatch_detected"] is False
        assert out["extra"] == "x"
        joined = " ".join(r.message for r in caplog.records)
        assert "llm_supplied_sentinel" in joined, (
            "operator-visible WARNING expected when stripping"
        )

    def test_single_shot_mismatch_strips_llm_supplied_sentinel(self):
        v = AlignmentResponseValidator()
        resp = (
            '{"mismatch_detected": true, "threat_name": "T", '
            '"summary": "s", "%s": true}' % _UNANALYSED_KEY
        )
        out = v.validate(resp)
        assert out is not None
        assert _UNANALYSED_KEY not in out
        assert out["mismatch_detected"] is True
        assert out["threat_name"] == "T"

    def test_clean_response_without_sentinel_is_untouched(self):
        v = AlignmentResponseValidator()
        resp = '{"mismatch_detected": false, "note": "all good"}'
        out = v.validate(resp)
        assert out == {"mismatch_detected": False, "note": "all good"}


# ---------------------------------------------------------------------------
# Post-review P3.2 — ``is_unanalysed`` is the supported way to test slot
# sentinel-ness from outside the validator module.
# ---------------------------------------------------------------------------


class TestIsUnanalysedHelper:
    """``is_unanalysed`` is the public contract for cross-module sentinel
    detection. The orchestrator already uses it; if we ever rename the
    internal key, downstream callers must keep working."""

    def test_sentinel_detected(self):
        assert is_unanalysed({"mismatch_detected": False, _UNANALYSED_KEY: True})

    def test_clean_dict_not_detected(self):
        assert not is_unanalysed({"mismatch_detected": False})
        assert not is_unanalysed({"mismatch_detected": True, "threat_name": "T"})

    @pytest.mark.parametrize(
        "value",
        [None, "", "_unanalysed", 0, [], object()],
    )
    def test_non_dict_inputs_are_safe(self, value):
        # Helper must never raise on arbitrary input — it sits behind
        # ``is None`` checks in the hot path.
        assert is_unanalysed(value) is False

    def test_falsy_sentinel_value_is_not_detected(self):
        # The orchestrator only routes on truthy sentinels; ``False``
        # should be treated as absent so an LLM cannot soft-poison the
        # path with ``"_unanalysed": false`` either.
        assert not is_unanalysed({"mismatch_detected": False, _UNANALYSED_KEY: False})


# ---------------------------------------------------------------------------
# Post-review P3.3 — adversarial-sentinel spoofing logs the batch-level
# WARNING once with the total count, not once per item.
# ---------------------------------------------------------------------------


class TestSpoofingLogAggregation:
    """Under adversarial input every batch item could carry
    ``_unanalysed``. The validator must emit per-item DEBUG breadcrumbs
    but only *one* WARNING with the aggregate count, otherwise operator
    log volume explodes proportional to ``batch_size``."""

    def test_single_warning_for_all_stripped_items(self, caplog):
        v = AlignmentResponseValidator()
        n = 10
        items = ",".join(
            '{"mismatch_detected": false, "%s": true}' % _UNANALYSED_KEY
            for _ in range(n)
        )
        resp = "[%s]" % items

        with caplog.at_level(
            logging.DEBUG,
            logger=(
                "mcpscanner.core.analyzers.behavioral.alignment."
                "alignment_response_validator"
            ),
        ):
            out = v.validate_batch(resp, expected_count=n)

        assert out is not None and len(out) == n
        assert all(_UNANALYSED_KEY not in item for item in out)

        warnings = [
            r for r in caplog.records
            if r.levelno == logging.WARNING and "llm_supplied_sentinel" in r.message
        ]
        assert len(warnings) == 1, (
            f"expected exactly one batch-level WARNING for {n} adversarial "
            f"items, got {len(warnings)}"
        )
        assert "stripped=%d" % n in warnings[0].message

        # Per-item DEBUG breadcrumbs still emitted for traceability.
        debugs = [
            r for r in caplog.records
            if r.levelno == logging.DEBUG and "llm_supplied_sentinel" in r.message
        ]
        assert len(debugs) == n
