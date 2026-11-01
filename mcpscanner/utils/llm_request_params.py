# Copyright 2025 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Model-specific LiteLLM request parameter adjustments."""

import re

# Claude models that reject sampling parameters such as ``temperature``.
_NO_TEMPERATURE_RE = re.compile(
    r"opus-4[-.][7-9]|opus-[5-9]|fable|sonnet-[5-9]|haiku-[5-9]"
)


def supports_temperature(model: str) -> bool:
    """Return whether ``temperature`` may be sent for this model.

    Opus 4.7 and later Claude models (Opus 4.8+, Opus 5.x, Sonnet 5.x,
    Haiku 5.x, Fable) reject ``temperature`` with a 400 (``temperature is
    deprecated for this model``) on every provider that serves them
    (Anthropic, Vertex AI, Bedrock), so the knob is omitted for them.
    """
    return not _NO_TEMPERATURE_RE.search((model or "").lower())


def apply_model_constraints(model: str, params: dict) -> None:
    """Adjust completion params for models with stricter API rules."""
    if not supports_temperature(model):
        params.pop("temperature", None)
    if "gpt-5" not in model.lower():
        return
    if "max_tokens" in params:
        params["max_completion_tokens"] = params.pop("max_tokens")
    params["temperature"] = 1
