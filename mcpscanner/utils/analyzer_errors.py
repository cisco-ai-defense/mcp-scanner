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
import re
from enum import Enum
from typing import Awaitable, Callable, Optional, TypeVar, Union

T = TypeVar("T")
OnRetryCallback = Callable[[BaseException, int, float], Union[None, Awaitable[None]]]


class ErrorKind(str, Enum):
    """Disposition of an analyzer-stage failure."""

    TRANSIENT = "transient"
    FINAL = "final"


# Stable tokens for structured logs / scan payloads.
ERROR_KIND_TRANSIENT = ErrorKind.TRANSIENT.value
ERROR_KIND_FINAL = ErrorKind.FINAL.value


_FINAL_STATUS_CODES = frozenset({401, 403})
_TRANSIENT_STATUS_CODES = frozenset({408, 429, 500, 502, 503, 504})

_FINAL_KEYWORDS = (
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
    "content blocked",
    "blocked by policy",
    "blocked by guardrail",
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
    "service unavailable",
    "bad gateway",
    "gateway timeout",
    "overloaded",
    "capacity",
    "temporarily unavailable",
    "temporarily blocked",
    "internal server error",
)

_BEDROCK_TRANSIENT_KEYWORDS = (
    "throttlingexception",
)

_LITELLM_TRANSIENT_TYPES: tuple[type[BaseException], ...] | None = None
_LITELLM_FINAL_TYPES: tuple[type[BaseException], ...] | None = None


def _is_bedrock_model(model: str | None) -> bool:
    return bool(model and "bedrock/" in model.lower())


def _exception_status_code(exc: BaseException) -> Optional[int]:
    status = getattr(exc, "status_code", None)
    if status is None:
        return None
    try:
        return int(status)
    except (TypeError, ValueError):
        return None


def _message_contains_status_code(message: str, code: int) -> bool:
    """Match HTTP status codes without hitting unrelated digit sequences."""
    return re.search(rf"(?<!\d){code}(?!\d)", message) is not None


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


def _get_litellm_type_tuples() -> tuple[
    tuple[type[BaseException], ...], tuple[type[BaseException], ...]
]:
    global _LITELLM_TRANSIENT_TYPES, _LITELLM_FINAL_TYPES
    if _LITELLM_TRANSIENT_TYPES is not None and _LITELLM_FINAL_TYPES is not None:
        return _LITELLM_TRANSIENT_TYPES, _LITELLM_FINAL_TYPES

    transient_types: list[type[BaseException]] = []
    final_types: list[type[BaseException]] = []
    try:
        import litellm
    except ImportError:
        _LITELLM_TRANSIENT_TYPES = tuple()
        _LITELLM_FINAL_TYPES = tuple()
        return _LITELLM_TRANSIENT_TYPES, _LITELLM_FINAL_TYPES

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

    _LITELLM_TRANSIENT_TYPES = tuple(transient_types)
    _LITELLM_FINAL_TYPES = tuple(final_types)
    return _LITELLM_TRANSIENT_TYPES, _LITELLM_FINAL_TYPES


def _litellm_error_kind(exc: BaseException) -> Optional[ErrorKind]:
    """Map litellm exception types when available."""
    transient_types, final_types = _get_litellm_type_tuples()
    if transient_types and isinstance(exc, transient_types):
        return ErrorKind.TRANSIENT
    if final_types and isinstance(exc, final_types):
        return ErrorKind.FINAL
    return None


def _message_has_transient_keyword(message: str, *, model: str | None) -> bool:
    if any(kw in message for kw in _TRANSIENT_KEYWORDS):
        return True
    if _is_bedrock_model(model):
        return any(kw in message for kw in _BEDROCK_TRANSIENT_KEYWORDS)
    return False


def classify_analyzer_error(
    exc: BaseException,
    *,
    context: str = "llm",
    model: str | None = None,
) -> ErrorKind:
    """Return whether ``exc`` should be retried (TRANSIENT) or not (FINAL).

    Args:
        exc: The raised exception.
        context: Where the failure occurred — ``llm`` (remote API),
            ``local`` (filesystem / AST / prompt build), or ``parse``
            (response validation). Defaults to ``llm``.
        model: Optional litellm model id (``bedrock/...`` gates Bedrock-only
            transient keyword matches).
    """
    if context == "local":
        return ErrorKind.FINAL

    status_code = _exception_status_code(exc)
    if status_code in _FINAL_STATUS_CODES:
        return ErrorKind.FINAL
    if status_code in _TRANSIENT_STATUS_CODES:
        return ErrorKind.TRANSIENT

    litellm_kind = _litellm_error_kind(exc)
    if litellm_kind is not None:
        return litellm_kind

    msg = _exception_message(exc)

    # Transient signals before final keyword / status heuristics so genuine
    # overload/timeout messages win over coincidental digit runs ("403 connections").
    if _message_has_transient_keyword(msg, model=model):
        return ErrorKind.TRANSIENT
    if any(
        _message_contains_status_code(msg, code)
        for code in _TRANSIENT_STATUS_CODES
    ):
        return ErrorKind.TRANSIENT

    if any(kw in msg for kw in _FINAL_KEYWORDS):
        return ErrorKind.FINAL
    if any(
        _message_contains_status_code(msg, code) for code in _FINAL_STATUS_CODES
    ):
        return ErrorKind.FINAL

    if context == "parse":
        # Malformed model output is often recoverable on re-prompt.
        return ErrorKind.TRANSIENT

    # Unknown LLM/API failures: fail fast — do not retry unrecognized errors.
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
    model: str | None = None,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    on_retry: OnRetryCallback | None = None,
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
            kind = classify_analyzer_error(exc, context=context, model=model)
            if kind is ErrorKind.FINAL or attempt >= max_attempts - 1:
                raise
            delay = compute_backoff_delay(attempt, base_delay)
            if on_retry is not None:
                maybe_coro = on_retry(exc, attempt + 1, delay)
                if asyncio.iscoroutine(maybe_coro):
                    await maybe_coro
            await sleep(delay)
    if last_exc is not None:
        raise last_exc
    raise RuntimeError("retry_transient_async exhausted without exception")


def build_infrastructure_error_finding(
    *,
    analyzer_name: str,
    subject: str,
    error: BaseException,
    context: str = "llm",
    model: str | None = None,
):
    """Return a visible finding when an analyzer stage fails entirely.

    Callers should emit this instead of returning an empty findings list so
    scan output cannot be mistaken for a clean LLM pass.
    """
    from ..core.analyzers.base import SecurityFinding
    from .log_format import ERROR_TRUNCATE, truncate

    kind = classify_analyzer_error(error, context=context, model=model)
    message = truncate(str(error), ERROR_TRUNCATE)
    details: dict[str, str] = {
        "subject": subject,
        "error": message,
        "error_kind": kind.value,
        "error_type": type(error).__name__,
    }
    if model:
        details["model"] = model
    return SecurityFinding(
        severity="INFO",
        summary=(
            f"{analyzer_name} analysis did not complete for {subject}: {message}"
        ),
        analyzer=analyzer_name,
        threat_category="ANALYZER INFRASTRUCTURE",
        details=details,
    )
