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


# Process-wide monotonic id factories so two ``AlignmentLLMClient``
# instances in the same process don't both emit ``request_id=1`` and
# collide in search results. The counters are best-effort (not thread-
# safe under freethreading) but adequate under the CPython GIL where
# ``next(...)`` is a single bytecode dispatch.
_PROCESS_CLIENT_IDS = itertools.count(1)
_PROCESS_REQUEST_IDS = itertools.count(1)


# Maximum length of an arbitrary string interpolated into an error log
# line. ``litellm`` exception messages can include multi-KB request body
# echoes (Bedrock dumps base64 payloads on validation failures); capping
# at this size keeps log lines bounded without losing the root cause.
_ERROR_TRUNCATE = 400
# Cap on the size of a raw response dump in DEBUG logs. Same rationale
# as the validator's prefix cap — keeps logs bounded when a hostile MCP
# server's tool description coaxes the model into a multi-KB reply.
_RESPONSE_DEBUG_MAX = 500


def _truncate(value: object, limit: int) -> str:
    """Stringify ``value`` and clip to ``limit`` chars with an ellipsis marker.

    Centralised so every log line that interpolates an LLM-controlled
    string (exception messages, response bodies) uses the same bound.
    The trailing ``…(+N)`` suffix lets operators see something was
    dropped without dumping it.
    """
    s = str(value)
    if len(s) <= limit:
        return s
    return f"{s[:limit]}…(+{len(s) - limit})"


def _classify_provider(model: str) -> str:
    """Return a short, log-safe provider label for the given litellm model id.

    Operators triage by provider (e.g. "is Bedrock slow today?") so this
    label is included on the init line and on the warning emitted for
    slow requests. Kept narrow on purpose — anything not on the known
    list collapses to ``"other"`` so a typo'd model name still produces
    a clean log message instead of a leaky prefix dump.

    The ``o1-`` / ``o3-`` prefixes are anchored with the trailing hyphen
    so a future model from a different provider that happens to start
    with ``o1`` or ``o3`` won't be mis-classified as OpenAI.
    """
    if not model:
        return "unknown"
    if model.startswith("bedrock/"):
        return "bedrock"
    if model.startswith("azure/"):
        return "azure"
    if model.startswith(("openai/", "gpt-", "o1-", "o3-", "chatgpt-")):
        return "openai"
    if model.startswith("anthropic/"):
        return "anthropic"
    if model.startswith("gemini/") or model.startswith("vertex_ai/"):
        return "google"
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

        Mirrors ``LLMAnalyzer``'s tiered authentication strategy so the
        behavioral path supports the same Bedrock options as the
        tool-metadata path:

          1. Non-Bedrock providers (OpenAI, Anthropic, Azure):
             ``llm_provider_api_key`` is required.
          2. Bedrock with API key (``MCP_SCANNER_LLM_API_KEY``): use it.
          3. Bedrock with bearer token
             (``AWS_BEARER_TOKEN_BEDROCK`` / ``Config.aws_bearer_token_bedrock``):
             forward as ``api_key``.
          4. Bedrock with neither: leave ``api_key`` unset and let
             litellm/boto3 resolve credentials from the AWS provider
             chain (profile / IAM role / web identity / session token).

        Args:
            config: Configuration containing LLM credentials and settings

        Raises:
            ValueError: If a non-Bedrock provider is configured but no
                ``llm_provider_api_key`` is set.
        """
        # Model configuration (read first so the auth branch can use it).
        self._model = config.llm_model
        self._max_tokens = config.llm_max_tokens
        self._temperature = config.llm_temperature
        self._llm_timeout = config.llm_timeout
        self._base_url = config.llm_base_url
        self._api_version = config.llm_api_version

        is_bedrock = bool(self._model and "bedrock/" in self._model)
        api_key = getattr(config, "llm_provider_api_key", None)
        bearer_token = getattr(config, "aws_bearer_token_bedrock", None)

        if not is_bedrock:
            if not api_key:
                raise ValueError(
                    "LLM provider API key is required for alignment verification"
                )
            self._api_key = api_key
        else:
            # Bedrock auth precedence: explicit api_key > bearer token > AWS provider chain.
            if api_key:
                self._api_key = api_key
            elif bearer_token:
                self._api_key = bearer_token
            else:
                # IAM role / profile / session token resolved by litellm/boto3.
                self._api_key = None

        # AWS-specific knobs (only forwarded for Bedrock requests).
        self._aws_region = config.aws_region_name if is_bedrock else None
        self._aws_session_token = config.aws_session_token if is_bedrock else None
        self._aws_profile_name = config.aws_profile_name if is_bedrock else None

        self.logger = logging.getLogger(__name__)
        # ``client_id`` is process-unique and emitted on the init line
        # below. The per-call ``request_id`` (assigned in
        # ``verify_alignment``) is drawn from a separate process-wide
        # sequence so two clients in the same process can be cleanly
        # disentangled in search results even though they share the
        # logger name. This replaces the previous per-instance counter
        # which would collide on ``request_id=1`` across instances.
        self._client_id = next(_PROCESS_CLIENT_IDS)
        # Bumped to INFO on init so operators see at-a-glance which model
        # + auth mode the behavioral analyzer is talking to without
        # having to flip the whole library to DEBUG. Emits exactly once
        # per AlignmentLLMClient instance.
        provider = _classify_provider(self._model)
        if is_bedrock:
            if self._api_key:
                # Don't leak which mode (key vs bearer); both look identical
                # downstream and the distinction is only useful in support tickets.
                auth_kind = "api_key_or_bearer"
            else:
                auth_kind = "aws_provider_chain"
            self.logger.info(
                "AlignmentLLMClient initialized client_id=%d provider=%s model=%s "
                "region=%s auth=%s timeout=%ss",
                self._client_id,
                provider,
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
                provider,
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
        # Stable id correlates the prompt-length / attempt-N / completed lines
        # for one logical verify_alignment() call. Drawn from a process-wide
        # sequence so two clients in the same process don't collide.
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
                # Single INFO milestone per successful verify_alignment call.
                # Operators get one searchable line per LLM round-trip
                # ("LLM request_id=42 ok") with all key timing metadata.
                self.logger.info(
                    "LLM request_id=%d ok provider=%s model=%s attempts=%d duration_ms=%d "
                    "prompt_length=%d response_length=%d",
                    request_id,
                    _classify_provider(self._model),
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
                        _truncate(e, _ERROR_TRUNCATE),
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
                        _truncate(e, _ERROR_TRUNCATE),
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

            # Only attach api_key when one was resolved. Bedrock with the
            # AWS provider chain (profile/IAM/session token) must reach
            # litellm with no api_key so boto3 can pick credentials up.
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

            # Forward AWS-specific routing parameters when running against
            # Bedrock so litellm/boto3 hit the right region/profile/session
            # token. These are stored as None for non-Bedrock models and
            # therefore never appear in the request kwargs in that case.
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

            # Pull token usage when the provider returned it. Bedrock /
            # OpenAI / Azure all expose ``usage`` on the response object;
            # treat as best-effort so a provider that omits it never
            # breaks the log line.
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

            # Log response for debugging
            if not content or not content.strip():
                self.logger.warning(
                    "LLM request_id=%d empty_response model=%s duration_ms=%d "
                    "prompt_tokens=%s completion_tokens=%s",
                    request_id,
                    self._model,
                    attempt_ms,
                    prompt_tokens,
                    completion_tokens,
                )
                # Cap the response dump so a hostile / pathological model
                # response can't bloat a single log line into multi-MB.
                # The full body is still available via the upstream
                # litellm logger at TRACE if needed.
                self.logger.debug(
                    "LLM request_id=%d full_response=%s",
                    request_id,
                    _truncate(repr(response), _RESPONSE_DEBUG_MAX),
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

            # Surface slow round-trips at WARNING so operators triaging
            # "scan feels slow" don't have to switch the library to
            # DEBUG just to see per-call timing. Threshold is configurable
            # via MCP_SCANNER_LLM_SLOW_REQUEST_THRESHOLD_MS.
            if attempt_ms >= MCPScannerConstants.LLM_SLOW_REQUEST_THRESHOLD_MS:
                self.logger.warning(
                    "LLM request_id=%d slow_response provider=%s model=%s "
                    "duration_ms=%d threshold_ms=%d -- check provider latency, "
                    "region routing, or model warm-up",
                    request_id,
                    _classify_provider(self._model),
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
                _truncate(e, _ERROR_TRUNCATE),
                self._model,
                exc_info=True,
            )
            raise
