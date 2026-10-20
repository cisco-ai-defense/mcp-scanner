# Copyright 2025 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Model-specific LiteLLM request parameter adjustments."""


def apply_model_constraints(model: str, params: dict) -> None:
    """Adjust completion params for models with stricter API rules."""
    if "gpt-5" not in model.lower():
        return
    if "max_tokens" in params:
        params["max_completion_tokens"] = params.pop("max_tokens")
    params["temperature"] = 1
