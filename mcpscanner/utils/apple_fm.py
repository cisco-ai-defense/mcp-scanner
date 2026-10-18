# Copyright 2025 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""On-device completions via Apple's Foundation Models Python SDK.

``apple-fm/<name>`` selects the system language model. No API key is
used: inference stays on the Mac that has Apple Intelligence enabled.
"""

from __future__ import annotations

import asyncio
import inspect
from typing import Any, Optional


_PREFIX = "apple-fm/"


def is_apple_fm_model(model: Optional[str]) -> bool:
    """Return True when ``model`` selects the on-device Foundation Model."""
    return bool(model) and model.lower().startswith(_PREFIX)


def apple_fm_runtime_status() -> tuple[bool, str]:
    """Return whether the on-device model can run, and why if it cannot."""
    try:
        import apple_fm_sdk as fm
    except ImportError:
        return (
            False,
            "apple-fm-sdk is not installed. Install it with: pip install apple-fm-sdk "
            "(macOS 26+, Apple Intelligence enabled).",
        )
    try:
        availability = fm.SystemLanguageModel().is_available()
    except Exception as exc:
        return False, f"Foundation Models not available: {exc}"
    if isinstance(availability, tuple):
        available = bool(availability[0])
        detail = availability[1] if len(availability) > 1 else None
        reason = detail or "unavailable"
    else:
        available = bool(availability)
        reason = "unavailable"
    if not available:
        return False, f"Foundation Models not available: {reason}"
    return True, ""


def model_allows_missing_api_key(model: Optional[str]) -> bool:
    """Bedrock (AWS creds) and Apple FM (on-device) do not need an API key."""
    if not model:
        return False
    lowered = model.lower()
    return "bedrock/" in lowered or lowered.startswith(_PREFIX)


class _Message:
    def __init__(self, content: str) -> None:
        self.content = content


class _Choice:
    def __init__(self, content: str) -> None:
        self.message = _Message(content)


class _Usage:
    prompt_tokens = None
    completion_tokens = None


class AppleFMResponse:
    """LiteLLM-shaped completion so existing callers can read ``choices``."""

    def __init__(self, content: str) -> None:
        self.choices = [_Choice(content)]
        self.usage = _Usage()


def _content_text(content: Any) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for part in content:
            if isinstance(part, dict):
                parts.append(str(part.get("text") or ""))
            else:
                parts.append(str(part))
        return "\n".join(part for part in parts if part)
    return str(content)


def _generation_options(fm: Any, params: dict) -> Any:
    """Map LiteLLM temperature and max token fields onto GenerationOptions."""
    options_cls = getattr(fm, "GenerationOptions", None)
    if options_cls is None:
        return None
    kwargs: dict = {}
    temperature = params.get("temperature")
    if temperature is not None and not isinstance(temperature, bool):
        kwargs["temperature"] = float(temperature)
    max_tokens = params.get("max_completion_tokens")
    if max_tokens is None:
        max_tokens = params.get("max_tokens")
    if max_tokens is not None and not isinstance(max_tokens, bool):
        limit = int(max_tokens)
        if limit > 0:
            kwargs["maximum_response_tokens"] = limit
    if not kwargs:
        return None
    return options_cls(**kwargs)


def _split_messages(messages: list) -> tuple[str, str]:
    system_parts = []
    user_parts = []
    for message in messages or []:
        if not isinstance(message, dict):
            user_parts.append(str(message))
            continue
        role = str(message.get("role") or "user").lower()
        text = _content_text(message.get("content"))
        if not text:
            continue
        if role == "system":
            system_parts.append(text)
        else:
            user_parts.append(text)
    return "\n\n".join(system_parts), "\n\n".join(user_parts)


async def apple_fm_acompletion(**params: Any) -> AppleFMResponse:
    """Run one prompt on the system Foundation Model.

    Accepts the same keyword arguments as a LiteLLM completion and ignores
    provider fields (``api_key``, ``drop_params``, and so on).
    """
    available, reason = apple_fm_runtime_status()
    if not available:
        if "not installed" in reason:
            raise ImportError(reason)
        raise RuntimeError(reason)
    import apple_fm_sdk as fm

    instructions, prompt = _split_messages(params.get("messages") or [])
    if not prompt:
        prompt = instructions
        instructions = ""

    session_kwargs: dict = {}
    try:
        signature = inspect.signature(fm.LanguageModelSession)
    except (TypeError, ValueError):
        signature = None
    if (
        instructions
        and signature is not None
        and "instructions" in signature.parameters
    ):
        session_kwargs["instructions"] = instructions
    elif instructions:
        prompt = f"{instructions}\n\n{prompt}"

    session = fm.LanguageModelSession(**session_kwargs)
    respond_kwargs: dict = {}
    options = _generation_options(fm, params)
    if options is not None:
        try:
            respond_signature = inspect.signature(session.respond)
        except (TypeError, ValueError):
            respond_signature = None
        if respond_signature is None or "options" in respond_signature.parameters:
            respond_kwargs["options"] = options

    async def _respond() -> Any:
        return await session.respond(prompt, **respond_kwargs)

    timeout = params.get("timeout")
    try:
        if timeout:
            raw = await asyncio.wait_for(_respond(), timeout=float(timeout))
        else:
            raw = await _respond()
    except TimeoutError as exc:
        if not timeout:
            raise
        raise TimeoutError(
            f"apple-fm request timed out after {timeout} seconds"
        ) from exc
    if isinstance(raw, str):
        text = raw
    else:
        text = str(getattr(raw, "content", raw))
    return AppleFMResponse(text)
