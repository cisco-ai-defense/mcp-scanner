# Copyright 2025 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for analyzer error classification and backoff helpers."""

import asyncio
from unittest.mock import AsyncMock

import pytest

from mcpscanner.utils.analyzer_errors import (
    ErrorKind,
    classify_analyzer_error,
    compute_backoff_delay,
    retry_transient_async,
)


class TestClassifyAnalyzerError:
    def test_transient_timeout(self):
        assert (
            classify_analyzer_error(TimeoutError("connection timed out"), context="llm")
            is ErrorKind.TRANSIENT
        )

    def test_transient_rate_limit_message(self):
        assert (
            classify_analyzer_error(RuntimeError("429 rate limit exceeded"), context="llm")
            is ErrorKind.TRANSIENT
        )

    def test_final_auth_error(self):
        assert (
            classify_analyzer_error(RuntimeError("401 unauthorized"), context="llm")
            is ErrorKind.FINAL
        )

    def test_final_local_syntax(self):
        assert (
            classify_analyzer_error(SyntaxError("bad syntax"), context="local")
            is ErrorKind.FINAL
        )

    def test_parse_context_defaults_transient(self):
        assert (
            classify_analyzer_error(ValueError("bad json"), context="parse")
            is ErrorKind.TRANSIENT
        )

    def test_transient_keyword_in_message(self):
        assert (
            classify_analyzer_error(RuntimeError("transient"), context="llm")
            is ErrorKind.TRANSIENT
        )

    def test_unknown_llm_error_defaults_final(self):
        """Unrecognized LLM failures fail fast instead of retrying."""
        assert (
            classify_analyzer_error(RuntimeError("weird provider glitch"), context="llm")
            is ErrorKind.FINAL
        )

    def test_coincidental_status_with_timeout_is_transient(self):
        assert (
            classify_analyzer_error(
                RuntimeError("dropped 403 connections due to timeout"),
                context="llm",
            )
            is ErrorKind.TRANSIENT
        )

    def test_temporarily_blocked_rate_limit_is_transient(self):
        assert (
            classify_analyzer_error(
                RuntimeError(
                    "request temporarily blocked due to rate limiting, retry later"
                ),
                context="llm",
            )
            is ErrorKind.TRANSIENT
        )

    def test_local_attribute_error_is_final(self):
        assert (
            classify_analyzer_error(
                AttributeError("missing field"), context="local"
            )
            is ErrorKind.FINAL
        )

    def test_bedrock_access_denied_is_final(self):
        assert (
            classify_analyzer_error(
                RuntimeError("BedrockException: AccessDenied"),
                context="llm",
                model="bedrock/anthropic.claude-sonnet-4-5-20250929-v2:0",
            )
            is ErrorKind.FINAL
        )

    def test_status_code_attribute_final(self):
        exc = RuntimeError("provider error")
        exc.status_code = 403  # type: ignore[attr-defined]
        assert classify_analyzer_error(exc, context="llm") is ErrorKind.FINAL

    def test_status_code_attribute_transient(self):
        exc = RuntimeError("provider error")
        exc.status_code = 503  # type: ignore[attr-defined]
        assert classify_analyzer_error(exc, context="llm") is ErrorKind.TRANSIENT

    def test_false_positive_status_substring_in_request_id(self):
        """Digits embedded in ids without transient signals are final (fail-fast)."""
        assert (
            classify_analyzer_error(
                RuntimeError("request req_1403abc failed"),
                context="llm",
            )
            is ErrorKind.FINAL
        )

    def test_false_positive_status_substring_in_token_count(self):
        """``1403`` embeds ``403`` but without signals is fail-fast final."""
        assert (
            classify_analyzer_error(
                RuntimeError("prompt tokens=1403"),
                context="llm",
            )
            is ErrorKind.FINAL
        )


class TestComputeBackoffDelay:
    def test_exponential_growth(self):
        assert compute_backoff_delay(0, 1.0) == 1.0
        assert compute_backoff_delay(1, 1.0) == 2.0
        assert compute_backoff_delay(2, 0.5) == 2.0

    def test_cap(self):
        assert compute_backoff_delay(10, 1.0, cap=30.0) == 30.0


class TestRetryTransientAsync:
    @pytest.mark.asyncio
    async def test_retries_transient_then_succeeds(self):
        calls = {"n": 0}

        async def op():
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("503 service unavailable")
            return "ok"

        result = await retry_transient_async(
            op,
            max_attempts=3,
            base_delay=0.0,
            sleep=AsyncMock(return_value=None),
        )
        assert result == "ok"
        assert calls["n"] == 2

    @pytest.mark.asyncio
    async def test_final_error_fails_fast(self):
        calls = {"n": 0}

        async def op():
            calls["n"] += 1
            raise RuntimeError("403 forbidden")

        with pytest.raises(RuntimeError, match="403"):
            await retry_transient_async(
                op,
                max_attempts=3,
                base_delay=0.0,
                sleep=AsyncMock(return_value=None),
            )
        assert calls["n"] == 1

    @pytest.mark.asyncio
    async def test_on_retry_callback_invoked_before_sleep(self):
        retries: list[tuple[int, float]] = []

        async def on_retry(_exc: BaseException, attempt: int, delay: float) -> None:
            retries.append((attempt, delay))

        calls = {"n": 0}

        async def op():
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("503 service unavailable")
            return "ok"

        result = await retry_transient_async(
            op,
            max_attempts=3,
            base_delay=0.0,
            sleep=AsyncMock(return_value=None),
            on_retry=on_retry,
        )
        assert result == "ok"
        assert retries == [(1, 0.0)]

    @pytest.mark.asyncio
    async def test_on_retry_callback_invoked_before_sleep(self):
        retries: list[tuple[int, float]] = []

        async def on_retry(_exc: BaseException, attempt: int, delay: float) -> None:
            retries.append((attempt, delay))

        calls = {"n": 0}

        async def op():
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("503 service unavailable")
            return "ok"

        result = await retry_transient_async(
            op,
            max_attempts=3,
            base_delay=0.0,
            sleep=AsyncMock(return_value=None),
            on_retry=on_retry,
        )
        assert result == "ok"
        assert retries == [(1, 0.0)]
