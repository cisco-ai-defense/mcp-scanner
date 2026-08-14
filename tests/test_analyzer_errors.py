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
