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

"""Classify analyzer failures as transient vs final and compute retry backoff.

Transient errors (network blips, rate limits, overloaded upstream) are
retried with exponential backoff. Final errors (auth, bad configuration,
local parse/preparation bugs) fail fast so operators get a clear signal
without amplifying load against an endpoint that cannot succeed.
"""

from __future__ import annotations

import asyncio
from enum import Enum
from typing import Awaitable, Callable, Optional, TypeVar

T = TypeVar("T")


class ErrorKind(str, Enum):
    """Disposition of an analyzer-stage failure."""

    TRANSIENT = "transient"
    FINAL = "final"


# Stable tokens for structured logs / scan payloads.
ERROR_KIND_TRANSIENT = ErrorKind.TRANSIENT.value
ERROR_KIND_FINAL = ErrorKind.FINAL.value


_FINAL_KEYWORDS = (
    "401",
    "403",
    "unauthorized",
    "forbidden",
    "access denied",
    "accessdenied",
    "invalid api key",
    "invalid_api_key",
    "authentication",
    "authenticationerror",
    "permission denied",
    "model not found",
    "model_not_found",
    "resourcenotfound",
    "validation error",
    "invalid request",
    "bad request",
    "context length",
    "maximum context",
    "token limit",
    "content_filter",
    "content filter",
    "safety",
    "blocked",
)

_TRANSIENT_KEYWORDS = (
    "transient",
    "timeout",
    "timed out",
    "time out",
    "connection reset",
    "connection refused",
    "connection error",
    "connection aborted",
    "network",
    "dns",
    "tls",
    "ssl",
    "handshake",
    "rate limit",
    "rate_limit",
    "ratelimit",
    "throttl",
    "quota",
    "too many requests",
    "429",
    "502",
    "503",
    "504",
    "408",
    "service unavailable",
    "bad gateway",
    "gateway timeout",
    "overloaded",
    "capacity",
    "temporarily unavailable",
    "bedrockexception",
    "throttlingexception",
    "internal server error",
    "500",
)


def _exception_message(exc: BaseException) -> str:
    parts = [str(exc).lower()]
    for attr in ("message", "body", "response"):
        val = getattr(exc, attr, None)
        if val is not None:
            parts.append(str(val).lower())
    status = getattr(exc, "status_code", None)
    if status is not None:
        parts.append(str(status))
    return " ".join(parts)


def _litellm_error_kind(exc: BaseException) -> Optional[ErrorKind]:
    """Map litellm exception types when available."""
    try:
        import litellm
    except ImportError:
        return None

    transient_types = []
    final_types = []
    for name in (
        "Timeout",
        "TimeoutError",
        "ServiceUnavailableError",
        "InternalServerError",
        "RateLimitError",
        "APIConnectionError",
    ):
        cls = getattr(litellm, name, None) or getattr(litellm.exceptions, name, None)
        if cls is not None:
            transient_types.append(cls)
    for name in (
        "AuthenticationError",
        "PermissionDeniedError",
        "BadRequestError",
        "NotFoundError",
        "InvalidRequestError",
    ):
        cls = getattr(litellm, name, None) or getattr(litellm.exceptions, name, None)
        if cls is not None:
            final_types.append(cls)

    if transient_types and isinstance(exc, tuple(transient_types)):
        return ErrorKind.TRANSIENT
    if final_types and isinstance(exc, tuple(final_types)):
        return ErrorKind.FINAL
    return None


def classify_analyzer_error(
    exc: BaseException,
    *,
    context: str = "llm",
) -> ErrorKind:
    """Return whether ``exc`` should be retried (TRANSIENT) or not (FINAL).

    Args:
        exc: The raised exception.
        context: Where the failure occurred — ``llm`` (remote API),
            ``local`` (filesystem / AST / prompt build), or ``parse``
            (response validation). Defaults to ``llm``.
    """
    litellm_kind = _litellm_error_kind(exc)
    if litellm_kind is not None:
        return litellm_kind

    if context == "local":
        if isinstance(exc, (FileNotFoundError, PermissionError, SyntaxError, UnicodeDecodeError)):
            return ErrorKind.FINAL
        if isinstance(exc, (ValueError, TypeError, KeyError, AttributeError)):
            return ErrorKind.FINAL
        return ErrorKind.FINAL

    msg = _exception_message(exc)

    if any(kw in msg for kw in _FINAL_KEYWORDS):
        return ErrorKind.FINAL

    if context == "parse":
        # Malformed model output is often recoverable on re-prompt.
        return ErrorKind.TRANSIENT

    if any(kw in msg for kw in _TRANSIENT_KEYWORDS):
        return ErrorKind.TRANSIENT

    # Unknown LLM/API failures: prefer retry (conservative for availability).
    if context == "llm":
        return ErrorKind.TRANSIENT

    return ErrorKind.FINAL


def compute_backoff_delay(attempt: int, base_delay: float, *, cap: float = 60.0) -> float:
    """Exponential backoff delay for attempt index ``attempt`` (0-based)."""
    delay = base_delay * (2**attempt)
    return min(delay, cap)


async def retry_transient_async(
    operation: Callable[[], Awaitable[T]],
    *,
    max_attempts: int,
    base_delay: float,
    context: str = "llm",
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> T:
    """Run ``operation`` until success or a final error / exhausted retries."""
    if max_attempts < 1:
        raise ValueError("max_attempts must be >= 1")

    last_exc: Optional[BaseException] = None
    for attempt in range(max_attempts):
        try:
            return await operation()
        except Exception as exc:
            last_exc = exc
            kind = classify_analyzer_error(exc, context=context)
            if kind is ErrorKind.FINAL or attempt >= max_attempts - 1:
                raise
            await sleep(compute_backoff_delay(attempt, base_delay))
    if last_exc is not None:
        raise last_exc
    raise RuntimeError("retry_transient_async exhausted without exception")
