# Copyright 2025 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Completion entry point used by scanner analyzers.

LiteLLM handles hosted providers. ``apple-fm/`` models are sent to the
on-device Foundation Models SDK instead.
"""

from __future__ import annotations

from typing import Any

from .apple_fm import (
    apple_fm_acompletion,
    is_apple_fm_model,
    model_allows_missing_api_key,
)

__all__ = ["acompletion", "is_apple_fm_model", "model_allows_missing_api_key"]


async def acompletion(**params: Any) -> Any:
    """Dispatch a chat completion to Apple FM or LiteLLM."""
    model = params.get("model") or ""
    if is_apple_fm_model(str(model)):
        return await apple_fm_acompletion(**params)
    from litellm import acompletion as litellm_acompletion

    return await litellm_acompletion(**params)
