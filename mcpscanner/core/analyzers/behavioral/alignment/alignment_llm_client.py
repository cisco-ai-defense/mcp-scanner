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

"""Alignment LLM Client for Semantic Verification.

This module handles all LLM API interactions specifically for semantic alignment
verification between MCP tool docstrings and their implementation.

The client manages:
- LLM configuration (API keys, endpoints, models)
- Request construction for alignment verification
- API communication via litellm
- Response retrieval
"""

import asyncio
import logging
from typing import Optional

from litellm import acompletion

from .....config.config import Config
from .....config.constants import MCPScannerConstants


class AlignmentLLMClient:
    """LLM client for semantic alignment verification queries.

    Handles communication with LLM providers (OpenAI, Azure, Bedrock, etc.)
    specifically for alignment verification tasks.

    Uses litellm for unified interface across providers and per-request
    parameter passing to avoid configuration conflicts.
    """

    def __init__(self, config: Config):
        """Initialize the alignment LLM client.

        Args:
            config: Configuration containing LLM credentials and settings

        Raises:
            ValueError: If LLM provider API key is not configured
        """
        if (
            not hasattr(config, "llm_provider_api_key")
            or not config.llm_provider_api_key
        ):
            raise ValueError(
                "LLM provider API key is required for alignment verification"
            )

        # Store configuration for per-request usage
        self._api_key = config.llm_provider_api_key
        self._base_url = config.llm_base_url
        self._api_version = config.llm_api_version

        # Model configuration
        self._model = config.llm_model
        self._max_tokens = config.llm_max_tokens
        self._temperature = config.llm_temperature
        self._llm_timeout = config.llm_timeout

        self.logger = logging.getLogger(__name__)
        self.logger.debug(f"AlignmentLLMClient initialized with model: {self._model}")

    # Models that support Anthropic-style ``cache_control`` markers
    # via litellm. OpenAI/Azure OpenAI already do automatic prefix
    # caching server-side and reject unknown keys, so we only mark
    # blocks as cacheable for these provider strings.
    _ANTHROPIC_CACHE_PREFIXES: tuple = (
        "anthropic/",
        "claude-",
        "bedrock/anthropic",
        "bedrock/us.anthropic",
        "bedrock/eu.anthropic",
        "bedrock/apac.anthropic",
    )

    def _supports_anthropic_cache(self) -> bool:
        """Return True when the configured model accepts ``cache_control``.

        Anthropic Claude (direct API), AWS Bedrock Claude, and the
        Vertex AI Anthropic family all honor litellm's
        ``cache_control: {"type": "ephemeral"}`` block. Other
        providers either cache automatically (OpenAI/Azure) or reject
        the marker, so we only emit it for known-supporting models.
        """
        if not MCPScannerConstants.LLM_PROMPT_CACHE_ENABLED:
            return False
        model = (self._model or "").lower()
        if any(model.startswith(p) for p in self._ANTHROPIC_CACHE_PREFIXES):
            return True
        if "claude" in model and "bedrock/" in model:
            return True
        return False

    async def verify_alignment(
        self,
        prompt: str,
        *,
        cacheable_template: Optional[str] = None,
        evidence: Optional[str] = None,
    ) -> str:
        """Send alignment verification prompt to LLM with retry logic.

        Two calling conventions:

        1. Legacy single-string mode (``prompt`` only): the entire
           template + evidence is sent as one user message. Kept for
           callers that haven't migrated to the split form.
        2. Cacheable mode (``cacheable_template`` AND ``evidence``):
           the static 73 KB threat-analysis template is placed in a
           dedicated system block tagged with Anthropic
           ``cache_control: ephemeral`` (when the configured model
           supports it). After the first request, subsequent requests
           reuse the cached prefix at ~10× cheaper input-token cost
           and noticeably lower TTFT. For non-Anthropic providers
           the two pieces are simply concatenated — OpenAI/Azure
           handle caching automatically without the marker.

        Args:
            prompt: Whole prompt (legacy) — ignored when
                ``cacheable_template`` and ``evidence`` are both set.
            cacheable_template: Static template to mark cacheable.
            evidence: Per-request evidence content. Kept short so each
                request only ships the variable portion.

        Returns:
            LLM response (JSON string)

        Raises:
            Exception: If LLM API call fails after retries
        """
        use_split = (
            cacheable_template is not None and evidence is not None
        )
        if use_split:
            total_length = len(cacheable_template) + len(evidence)
        else:
            total_length = len(prompt)

        self.logger.debug(f"Prompt length: {total_length} characters")
        if total_length > MCPScannerConstants.PROMPT_LENGTH_THRESHOLD:
            self.logger.warning(
                f"Large prompt detected: {total_length} characters "
                f"(threshold: {MCPScannerConstants.PROMPT_LENGTH_THRESHOLD}) - may be truncated by LLM"
            )

        # Retry logic with exponential backoff (configurable via constants)
        max_retries = MCPScannerConstants.LLM_MAX_RETRIES
        base_delay = MCPScannerConstants.LLM_RETRY_BASE_DELAY

        for attempt in range(max_retries):
            try:
                if use_split:
                    return await self._make_llm_request(
                        prompt=None,
                        cacheable_template=cacheable_template,
                        evidence=evidence,
                    )
                return await self._make_llm_request(prompt=prompt)
            except Exception as e:
                if attempt < max_retries - 1:
                    delay = base_delay * (2**attempt)
                    self.logger.warning(
                        f"LLM request failed (attempt {attempt + 1}/{max_retries}): {e}. Retrying in {delay}s..."
                    )
                    await asyncio.sleep(delay)
                else:
                    self.logger.error(
                        f"LLM request failed after {max_retries} attempts: {e}"
                    )
                    raise

    async def _make_llm_request(
        self,
        prompt: Optional[str] = None,
        *,
        cacheable_template: Optional[str] = None,
        evidence: Optional[str] = None,
    ) -> str:
        """Make a single LLM API request.

        Builds the message payload either as a single user prompt
        (legacy path) or as a system+user pair where the system block
        carries the static template and is marked cacheable for
        Anthropic-family models.

        Args:
            prompt: Single combined prompt (legacy).
            cacheable_template: Static template (cacheable path).
            evidence: Per-request evidence (cacheable path).

        Returns:
            LLM response content

        Raises:
            Exception: If API call fails
        """
        try:
            base_system = (
                "You are a security expert analyzing MCP tools. "
                "You receive complete dataflow, taint analysis, and code context. "
                "Analyze if the docstring accurately describes what the code actually does. "
                "Respond ONLY with valid JSON. Do not include any markdown formatting or code blocks."
            )

            if cacheable_template is not None and evidence is not None:
                if self._supports_anthropic_cache():
                    # Anthropic / Bedrock Anthropic: split the system
                    # block into preamble + cached template. The
                    # ``cache_control`` marker is per-block; its
                    # contents must be ≥1024 tokens for caching to
                    # actually engage (the 73 KB template is well
                    # over that threshold, so we always qualify).
                    system_content = [
                        {"type": "text", "text": base_system},
                        {
                            "type": "text",
                            "text": cacheable_template,
                            "cache_control": {"type": "ephemeral"},
                        },
                    ]
                else:
                    # OpenAI / Azure: automatic prefix caching kicks
                    # in for stable system content; no marker needed.
                    # Concatenate into a plain string so we don't ship
                    # a content-block list to providers that don't
                    # accept it.
                    system_content = f"{base_system}\n\n{cacheable_template}"
                messages = [
                    {"role": "system", "content": system_content},
                    {"role": "user", "content": evidence},
                ]
            else:
                messages = [
                    {"role": "system", "content": base_system},
                    {"role": "user", "content": prompt or ""},
                ]

            request_params = {
                "model": self._model,
                "messages": messages,
                "max_tokens": self._max_tokens,
                "temperature": self._temperature,
                "timeout": self._llm_timeout,
                "api_key": self._api_key,
            }

            # Only enable JSON mode for supported models/providers
            # Azure OpenAI with older API versions may not support this
            if not self._model.startswith("azure/"):
                request_params["response_format"] = {"type": "json_object"}

            # Add optional parameters if configured
            if self._base_url:
                request_params["api_base"] = self._base_url
            if self._api_version:
                request_params["api_version"] = self._api_version

            self.logger.debug(
                f"Sending alignment verification request to {self._model}"
            )
            self.logger.debug(f"Sending request to model: {self._model}")
            response = await acompletion(**request_params)

            # Extract content from response
            content = response.choices[0].message.content

            # Log response for debugging
            if not content or not content.strip():
                self.logger.warning(f"Empty response from LLM model {self._model}")
                self.logger.debug(f"Full response object: {response}")
            else:
                self.logger.debug(f"LLM response length: {len(content)} chars")

            return content if content else ""

        except Exception as e:
            self.logger.error(f"LLM alignment verification failed: {e}", exc_info=True)
            raise
