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
import itertools
import logging
import time

from litellm import acompletion

from .....config.config import Config
from .....config.constants import MCPScannerConstants
from .....utils.bedrock import ensure_bedrock_dependencies
from .....utils.log_format import ERROR_TRUNCATE, RESPONSE_DEBUG_MAX, truncate


# Process-wide, monotonically increasing counters used for log
# correlation. They intentionally never reset — even between tests — so
# assertions on absolute values (``request_id=1``) will be flaky.
# Tests should assert *relative* monotonicity or pattern-match on
# ``request_id=(\d+)``.
_PROCESS_CLIENT_IDS = itertools.count(1)
_PROCESS_REQUEST_IDS = itertools.count(1)


_PROVIDER_PREFIXES = {
    "bedrock": "bedrock",
    "azure": "azure",
    "openai": "openai",
    "anthropic": "anthropic",
    "gemini": "google",
    "vertex_ai": "google",
    "cohere": "cohere",
    "mistral": "mistral",
    "groq": "groq",
    "ollama": "ollama",
    "huggingface": "huggingface",
}


def _classify_provider(model: str) -> str:
    """Return a short, log-safe provider label for the given litellm model id.

    Resolution order:
    1. ``provider/model`` form — first path segment maps via
       :data:`_PROVIDER_PREFIXES`, unknown segments echo back verbatim.
    2. Bare model name — narrow list of well-known OpenAI prefixes
       (``gpt-``, ``o1-``, ``o3-``, ``chatgpt-``) so litellm's
       backwards-compatible "bare GPT" aliases still classify cleanly.
    3. Otherwise ``other``.
    """
    if not model:
        return "unknown"
    if "/" in model:
        prefix, _, _ = model.partition("/")
        return _PROVIDER_PREFIXES.get(prefix, prefix or "other")
    if model.startswith(("gpt-", "o1-", "o3-", "chatgpt-")):
        return "openai"
    return "other"


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
            ValueError: If a non-Bedrock provider is configured but no
                ``llm_provider_api_key`` is set.
        """
        self._model = config.llm_model
        self._max_tokens = config.llm_max_tokens
        self._temperature = config.llm_temperature
        self._llm_timeout = config.llm_timeout
        self._base_url = config.llm_base_url
        self._api_version = config.llm_api_version

        is_bedrock = bool(self._model and "bedrock/" in self._model)

        # Fail fast with an actionable message if boto3 is missing, instead of
        # litellm's opaque "No module named 'boto3'" at request time.
        if is_bedrock:
            ensure_bedrock_dependencies(self._model)

        api_key = getattr(config, "llm_provider_api_key", None)
        bearer_token = getattr(config, "aws_bearer_token_bedrock", None)

        if not is_bedrock:
            if not api_key:
                raise ValueError(
                    "LLM provider API key is required for alignment verification"
                )
            self._api_key = api_key
        else:
            if api_key:
                self._api_key = api_key
            elif bearer_token:
                self._api_key = bearer_token
            else:
                self._api_key = None

        self._aws_region = config.aws_region_name if is_bedrock else None
        self._aws_session_token = config.aws_session_token if is_bedrock else None
        self._aws_profile_name = config.aws_profile_name if is_bedrock else None

        self.logger = logging.getLogger(__name__)
        self._client_id = next(_PROCESS_CLIENT_IDS)
        self._provider = _classify_provider(self._model)
        if is_bedrock:
            if self._api_key:
                auth_kind = "api_key_or_bearer"
            else:
                auth_kind = "aws_provider_chain"
            self.logger.info(
                "AlignmentLLMClient initialized client_id=%d provider=%s model=%s "
                "region=%s auth=%s timeout=%ss",
                self._client_id,
                self._provider,
                self._model,
                self._aws_region,
                auth_kind,
                self._llm_timeout,
            )
        else:
            self.logger.info(
                "AlignmentLLMClient initialized client_id=%d provider=%s model=%s "
                "base_url=%s api_version=%s timeout=%ss",
                self._client_id,
                self._provider,
                self._model,
                self._base_url or "default",
                self._api_version or "default",
                self._llm_timeout,
            )

    async def verify_alignment(self, prompt: str) -> str:
        """Send alignment verification prompt to LLM with retry logic.

        Args:
            prompt: Comprehensive prompt with alignment verification evidence

        Returns:
            LLM response (JSON string)

        Raises:
            Exception: If LLM API call fails after retries
        """
        request_id = next(_PROCESS_REQUEST_IDS)

        # Log prompt length for debugging
        prompt_length = len(prompt)
        self.logger.debug(
            "LLM request_id=%d prompt_length=%d model=%s",
            request_id,
            prompt_length,
            self._model,
        )

        # Check against configurable threshold
        if prompt_length > MCPScannerConstants.PROMPT_LENGTH_THRESHOLD:
            self.logger.warning(
                "LLM request_id=%d large_prompt prompt_length=%d threshold=%d model=%s "
                "-- may be truncated by the model",
                request_id,
                prompt_length,
                MCPScannerConstants.PROMPT_LENGTH_THRESHOLD,
                self._model,
            )

        # Retry logic with exponential backoff (configurable via constants)
        max_retries = MCPScannerConstants.LLM_MAX_RETRIES
        base_delay = MCPScannerConstants.LLM_RETRY_BASE_DELAY
        verify_start = time.perf_counter()

        for attempt in range(max_retries):
            try:
                response = await self._make_llm_request(prompt, request_id, attempt + 1)
                total_ms = int((time.perf_counter() - verify_start) * 1000)
                self.logger.info(
                    "LLM request_id=%d ok provider=%s model=%s attempts=%d duration_ms=%d "
                    "prompt_length=%d response_length=%d",
                    request_id,
                    self._provider,
                    self._model,
                    attempt + 1,
                    total_ms,
                    prompt_length,
                    len(response) if response else 0,
                )
                return response
            except Exception as e:
                if attempt < max_retries - 1:
                    delay = base_delay * (2**attempt)
                    self.logger.warning(
                        "LLM request_id=%d retry attempt=%d/%d error_type=%s "
                        "error=%s backoff_s=%.1f model=%s",
                        request_id,
                        attempt + 1,
                        max_retries,
                        type(e).__name__,
                        truncate(e, ERROR_TRUNCATE),
                        delay,
                        self._model,
                    )
                    await asyncio.sleep(delay)
                else:
                    total_ms = int((time.perf_counter() - verify_start) * 1000)
                    self.logger.error(
                        "LLM request_id=%d failed attempts=%d duration_ms=%d "
                        "error_type=%s error=%s model=%s",
                        request_id,
                        max_retries,
                        total_ms,
                        type(e).__name__,
                        truncate(e, ERROR_TRUNCATE),
                        self._model,
                    )
                    raise

    async def _make_llm_request(
        self, prompt: str, request_id: int = 0, attempt: int = 1
    ) -> str:
        """Make a single LLM API request.

        Args:
            prompt: Prompt to send
            request_id: Caller-supplied id so retries share a correlation
                key. Defaults to 0 for direct callers (rare in practice;
                ``verify_alignment`` always supplies a real id).
            attempt: 1-based attempt number for retry visibility.

        Returns:
            LLM response content

        Raises:
            Exception: If API call fails
        """
        attempt_start = time.perf_counter()
        try:
            request_params = {
                "model": self._model,
                "messages": [
                    {
                        "role": "system",
                        "content": (
                            "You are a security expert analyzing MCP tools. "
                            "You receive complete dataflow, taint analysis, and code context. "
                            "Analyze if the docstring accurately describes what the code actually does. "
                            "Respond ONLY with valid JSON. Do not include any markdown formatting or code blocks."
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
                "max_tokens": self._max_tokens,
                "temperature": self._temperature,
                "timeout": self._llm_timeout,
            }

            if self._api_key:
                request_params["api_key"] = self._api_key

            # Only enable JSON mode for supported models/providers
            # Azure OpenAI with older API versions may not support this
            if not self._model.startswith("azure/"):
                request_params["response_format"] = {"type": "json_object"}

            # Add optional parameters if configured
            if self._base_url:
                request_params["api_base"] = self._base_url
            if self._api_version:
                request_params["api_version"] = self._api_version

            if self._aws_region:
                request_params["aws_region_name"] = self._aws_region
            if self._aws_session_token:
                request_params["aws_session_token"] = self._aws_session_token
            if self._aws_profile_name:
                request_params["aws_profile_name"] = self._aws_profile_name

            self.logger.debug(
                "LLM request_id=%d attempt=%d sending model=%s temperature=%s "
                "max_tokens=%d",
                request_id,
                attempt,
                self._model,
                self._temperature,
                self._max_tokens,
            )
            response = await acompletion(**request_params)

            # Extract content from response
            content = response.choices[0].message.content

            attempt_ms = int((time.perf_counter() - attempt_start) * 1000)

            usage = getattr(response, "usage", None) or {}
            prompt_tokens = (
                getattr(usage, "prompt_tokens", None)
                if not isinstance(usage, dict)
                else usage.get("prompt_tokens")
            )
            completion_tokens = (
                getattr(usage, "completion_tokens", None)
                if not isinstance(usage, dict)
                else usage.get("completion_tokens")
            )

            if not content or not content.strip():
                # DEBUG, not WARNING: the downstream validator emits a
                # single WARNING for the same condition. Two WARNINGs
                # per empty response is noise for operators.
                self.logger.debug(
                    "LLM request_id=%d empty_response model=%s duration_ms=%d "
                    "prompt_tokens=%s completion_tokens=%s full_response=%s",
                    request_id,
                    self._model,
                    attempt_ms,
                    prompt_tokens,
                    completion_tokens,
                    truncate(repr(response), RESPONSE_DEBUG_MAX),
                )
            else:
                self.logger.debug(
                    "LLM request_id=%d attempt=%d response_length=%d duration_ms=%d "
                    "prompt_tokens=%s completion_tokens=%s",
                    request_id,
                    attempt,
                    len(content),
                    attempt_ms,
                    prompt_tokens,
                    completion_tokens,
                )

            if attempt_ms >= MCPScannerConstants.LLM_SLOW_REQUEST_THRESHOLD_MS:
                self.logger.warning(
                    "LLM request_id=%d slow_response provider=%s model=%s "
                    "duration_ms=%d threshold_ms=%d -- check provider latency, "
                    "region routing, or model warm-up",
                    request_id,
                    self._provider,
                    self._model,
                    attempt_ms,
                    MCPScannerConstants.LLM_SLOW_REQUEST_THRESHOLD_MS,
                )

            return content if content else ""

        except Exception as e:
            attempt_ms = int((time.perf_counter() - attempt_start) * 1000)
            self.logger.error(
                "LLM request_id=%d attempt=%d failed duration_ms=%d error_type=%s error=%s "
                "model=%s",
                request_id,
                attempt,
                attempt_ms,
                type(e).__name__,
                truncate(e, ERROR_TRUNCATE),
                self._model,
                exc_info=True,
            )
            raise
