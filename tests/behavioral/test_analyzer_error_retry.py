# Copyright 2025 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Failure-path tests for transient/final error classification and retries."""

from __future__ import annotations

import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from mcpscanner.config.constants import MCPScannerConstants
from mcpscanner.core.analyzers.behavioral.alignment.alignment_llm_client import (
    AlignmentLLMClient,
)
from mcpscanner.core.analyzers.behavioral.alignment.alignment_orchestrator import (
    AlignmentOrchestrator,
)
from mcpscanner.utils.analyzer_errors import ERROR_KIND_FINAL, ERROR_KIND_TRANSIENT
from tests.behavioral.test_logging_contracts import (
    _non_bedrock_config,
    _stub_acompletion_response,
)


def _cfg():
    return _non_bedrock_config()


def _ctx(name: str = "tool_a"):
    return SimpleNamespace(name=name)


class TestAlignmentLLMFailurePaths:
    @pytest.mark.asyncio
    async def test_final_error_does_not_retry(self, caplog):
        client = AlignmentLLMClient(_cfg())
        mock = AsyncMock(
            side_effect=RuntimeError("401 unauthorized invalid api key")
        )
        with patch(
            "mcpscanner.core.analyzers.behavioral.alignment."
            "alignment_llm_client.acompletion",
            new=mock,
        ):
            with caplog.at_level(logging.WARNING):
                with pytest.raises(RuntimeError):
                    await client.verify_alignment("hello")

        assert mock.await_count == 1
        assert not any(" retry " in r.getMessage() for r in caplog.records)

    @pytest.mark.asyncio
    async def test_transient_error_retries_then_succeeds(self, caplog):
        client = AlignmentLLMClient(_cfg())
        mock = AsyncMock(
            side_effect=[
                RuntimeError("503 service unavailable"),
                _stub_acompletion_response('{"mismatch_detected": false}'),
            ]
        )
        with patch(
            "mcpscanner.core.analyzers.behavioral.alignment."
            "alignment_llm_client.acompletion",
            new=mock,
        ):
            with patch(
                "mcpscanner.utils.analyzer_errors.asyncio.sleep",
                new=AsyncMock(return_value=None),
            ):
                with caplog.at_level(logging.WARNING):
                    out = await client.verify_alignment("hello")

        assert mock.await_count == 2
        assert "mismatch_detected" in out
        retry_lines = [r for r in caplog.records if " retry " in r.getMessage()]
        assert retry_lines
        assert ERROR_KIND_TRANSIENT in retry_lines[0].getMessage()

    @pytest.mark.asyncio
    async def test_unknown_error_does_not_retry(self, caplog):
        client = AlignmentLLMClient(_cfg())
        mock = AsyncMock(side_effect=RuntimeError("novel provider failure xyz"))
        with patch(
            "mcpscanner.core.analyzers.behavioral.alignment."
            "alignment_llm_client.acompletion",
            new=mock,
        ):
            with caplog.at_level(logging.WARNING):
                with pytest.raises(RuntimeError):
                    await client.verify_alignment("hello")

        assert mock.await_count == 1

    @pytest.mark.asyncio
    async def test_max_retries_zero_raises(self):
        client = AlignmentLLMClient(_cfg())
        with pytest.raises(ValueError, match="max_retries must be >= 1"):
            await client.verify_alignment("hello", max_retries=0)

    @pytest.mark.asyncio
    async def test_transient_exhausted_logs_final_failure_kind(self, caplog):
        client = AlignmentLLMClient(_cfg())
        with patch.object(MCPScannerConstants, "LLM_MAX_RETRIES", 2):
            mock = AsyncMock(side_effect=RuntimeError("504 gateway timeout"))
            with patch(
                "mcpscanner.core.analyzers.behavioral.alignment."
                "alignment_llm_client.acompletion",
                new=mock,
            ):
                with patch(
                    "mcpscanner.utils.analyzer_errors.asyncio.sleep",
                    new=AsyncMock(return_value=None),
                ):
                    with caplog.at_level(logging.ERROR):
                        with pytest.raises(RuntimeError):
                            await client.verify_alignment("hello")

        assert mock.await_count == 2
        failed = [r for r in caplog.records if " failed " in r.getMessage()]
        assert failed
        assert ERROR_KIND_TRANSIENT in failed[-1].getMessage()


class TestOrchestratorFailureClassification:
    @pytest.mark.asyncio
    async def test_prompt_build_failure_increments_final_counter(self):
        orch = AlignmentOrchestrator(_cfg())
        orch.prompt_builder = SimpleNamespace(
            build_prompt=lambda _c: (_ for _ in ()).throw(
                AttributeError("bad context")
            )
        )
        orch.llm_client = SimpleNamespace(
            verify_alignment=AsyncMock(return_value='{"mismatch_detected": false}')
        )

        await orch.check_alignment(_ctx("local_bug"))

        assert orch.stats["skipped_error"] == 1
        assert orch.stats["skipped_error_final"] == 1
        assert orch.stats["skipped_error_transient"] == 0

    @pytest.mark.asyncio
    async def test_transient_llm_failure_increments_transient_counter(self):
        orch = AlignmentOrchestrator(_cfg())
        orch.prompt_builder = SimpleNamespace(build_prompt=lambda _c: "p")

        async def _transient(_p):
            raise RuntimeError("503 service unavailable")

        orch.llm_client = SimpleNamespace(verify_alignment=_transient)
        await orch.check_alignment(_ctx("transient_tool"))

        assert orch.stats["skipped_error"] == 1
        assert orch.stats["skipped_error_transient"] == 1
        assert orch.stats["skipped_error_final"] == 0
        assert "transient_tool" in orch.errored_function_names

    @pytest.mark.asyncio
    async def test_final_llm_failure_increments_final_counter(self):
        orch = AlignmentOrchestrator(_cfg())
        orch.prompt_builder = SimpleNamespace(build_prompt=lambda _c: "p")

        async def _final(_p):
            raise RuntimeError("403 forbidden access denied")

        orch.llm_client = SimpleNamespace(verify_alignment=_final)
        await orch.check_alignment(_ctx("final_tool"))

        assert orch.stats["skipped_error"] == 1
        assert orch.stats["skipped_error_transient"] == 0
        assert orch.stats["skipped_error_final"] == 1
        assert "final_tool" in orch.errored_function_names


class TestBatchParseFailureRetry:
    @pytest.mark.asyncio
    async def test_unparseable_batch_retries_before_fallback(self, monkeypatch):
        orch = AlignmentOrchestrator(_cfg())
        orch.prompt_builder = SimpleNamespace(
            build_batch_analysis_content=lambda batch: f"batch:{len(batch)}",
            wrap_batch_prompt=lambda batch, body: body,
        )

        calls = {"n": 0}

        async def _verify(_prompt, **kwargs):
            calls["n"] += 1
            return "{}"

        orch.llm_client = SimpleNamespace(verify_alignment=_verify)

        validate_calls = {"n": 0}

        def _validate(_response, expected):
            validate_calls["n"] += 1
            if validate_calls["n"] == 1:
                return None
            return [{"mismatch_detected": False}] * expected

        orch.response_validator = SimpleNamespace(validate_batch=_validate)
        orch.threat_vuln_classifier = SimpleNamespace(
            classify_finding=AsyncMock(return_value=None)
        )

        monkeypatch.setattr(
            "mcpscanner.core.analyzers.behavioral.alignment."
            "alignment_orchestrator.asyncio.sleep",
            AsyncMock(return_value=None),
        )
        monkeypatch.setattr(
            MCPScannerConstants,
            "LLM_BATCH_PARSE_MAX_ATTEMPTS",
            2,
        )

        results = await orch.check_alignment_batch([_ctx("x")], batch_size=1)

        assert calls["n"] == 2
        assert validate_calls["n"] == 2
        assert results == []
        assert orch.stats["no_mismatch"] == 1
