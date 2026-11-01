# Copyright 2025 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Model-specific LiteLLM request parameter adjustments."""


def supports_temperature(model: str) -> bool:
    """Return whether ``temperature`` may be sent for this model.

    Opus 4.7 rejects ``temperature`` with a 400 (``temperature is deprecated
    for this model``) on every provider that serves it (Anthropic, Vertex AI,
    Bedrock), so the knob is omitted for it.
    """
    return "opus-4-7" not in (model or "").lower()


def apply_model_constraints(model: str, params: dict) -> None:
    """Adjust completion params for models with stricter API rules."""
    if not supports_temperature(model):
        params.pop("temperature", None)
    if "gpt-5" not in model.lower():
        return
    if "max_tokens" in params:
        params["max_completion_tokens"] = params.pop("max_tokens")
    params["temperature"] = 1
