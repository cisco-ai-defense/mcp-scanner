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
        if is_bedrock:
            if self._api_key:
                # Don't leak which mode (key vs bearer); both look identical
                # downstream and the distinction is only useful in support tickets.
                auth_kind = "api_key/bearer_token"
            else:
                auth_kind = "AWS provider chain (profile/IAM/session)"
            self.logger.debug(
                "AlignmentLLMClient initialized with bedrock model=%s region=%s auth=%s",
                self._model,
                self._aws_region,
                auth_kind,
            )
        else:
            self.logger.debug(
                "AlignmentLLMClient initialized with model: %s", self._model
            )

    # Short security-expert preamble that lives in the system role
    # alongside the (much larger) framework template. Kept tight on
    # purpose — Anthropic-on-Bedrock penalises long, instruction-heavy
    # system messages with empty ``{}`` responses, so the bulk of the
    # framework guidance is appended via ``system_prompt`` from the
    # prompt builder rather than being baked in here.
    _BASE_SYSTEM_PREAMBLE = (
        "You are a security expert analyzing MCP tools. "
        "You receive complete dataflow, taint analysis, and code context. "
        "Analyze if the docstring accurately describes what the code actually does. "
        "Respond ONLY with valid JSON. Do not include any markdown formatting or code blocks."
    )

    async def verify_alignment(
        self, prompt: str, *, system_prompt: Optional[str] = None
    ) -> str:
        """Send alignment verification prompt to LLM with retry logic.

        Args:
            prompt: User-role payload with the per-function or per-batch
                evidence the model should analyse. This should contain
                ONLY the evidence (delimited untrusted-input block); the
                framework template belongs in ``system_prompt``.
            system_prompt: Optional system-role content (typically the
                73 KB framework template returned by
                ``AlignmentPromptBuilder.build_prompt_parts``). When
                provided it is concatenated after the built-in
                ``_BASE_SYSTEM_PREAMBLE``; when ``None`` the legacy
                "everything in the user role" shape is preserved for
                backward compatibility.

        Returns:
            LLM response (JSON string)

        Raises:
            Exception: If LLM API call fails after retries
        """
        # Log prompt length for debugging. We surface user, system, and
        # combined lengths individually so reviewers can tell at a glance
        # which side is dominating (the system slot now carries the
        # framework template; the user slot carries per-call evidence).
        prompt_length = len(prompt)
        system_length = len(system_prompt) if system_prompt else 0
        total_length = prompt_length + system_length
        self.logger.debug(
            "Alignment request lengths: user=%d system=%d total=%d characters",
            prompt_length,
            system_length,
            total_length,
        )

        # Check against configurable threshold. The threshold is about
        # context-window crowding ("may be truncated by LLM") and the
        # model sees both messages, so we compare against the combined
        # length. Pre-PR this was equivalent to ``prompt_length`` because
        # the entire framework template lived in the user role; after the
        # Bedrock prompt-shape fix the bulk rides in ``system_prompt`` so
        # checking only the user side would silently disable the warning
        # for every alignment call.
        if total_length > MCPScannerConstants.PROMPT_LENGTH_THRESHOLD:
            self.logger.warning(
                "Large prompt detected: total=%d characters (user=%d, system=%d) "
                "exceeds threshold %d - may be truncated by LLM",
                total_length,
                prompt_length,
                system_length,
                MCPScannerConstants.PROMPT_LENGTH_THRESHOLD,
            )

        # Retry logic with exponential backoff (configurable via constants)
        max_retries = MCPScannerConstants.LLM_MAX_RETRIES
        base_delay = MCPScannerConstants.LLM_RETRY_BASE_DELAY

        for attempt in range(max_retries):
            try:
                return await self._make_llm_request(
                    prompt, system_prompt=system_prompt
                )
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

    def _supports_native_json_mode(self) -> bool:
        """Return True if the configured model supports ``response_format=json_object``.

        Empirically only OpenAI direct honours ``response_format`` cleanly
        across the model lineup. Bedrock-hosted Anthropic short-circuits
        on long prompts and returns ``{}``; Bedrock Cohere/Titan reject
        the flag outright; Azure OpenAI on older API versions ignores or
        rejects it, which is why the prior code path explicitly excluded
        Azure too (see ``test_alignment_llm_client_bedrock`` regression).

        We intentionally allowlist by prefix rather than denylist so
        adding a new exotic provider doesn't accidentally re-enable the
        flag for a model that can't handle it. JSON output is still
        reliably coaxed via the system-prompt instruction in
        :data:`_BASE_SYSTEM_PREAMBLE`.
        """
        if not self._model:
            return False
        model = self._model.lower()
        # OpenAI direct: ``openai/...`` or bare ``gpt-*`` / ``o1-*`` /
        # ``o3-*`` / ``chatgpt-*`` model ids that litellm resolves to
        # the OpenAI provider. Azure (``azure/...``) is intentionally
        # excluded — older api-versions don't accept the flag and the
        # behavioral suite locks that contract.
        openai_prefixes = ("openai/", "gpt-", "o1-", "o1", "o3-", "o3", "chatgpt-")
        if model.startswith(openai_prefixes):
            return True
        # Everything else (Azure/Bedrock/Anthropic/Cohere/Vertex/...):
        # rely on the system-prompt instruction. See module docstring of
        # alignment_orchestrator for why this matters.
        return False

    async def _make_llm_request(
        self, prompt: str, *, system_prompt: Optional[str] = None
    ) -> str:
        """Make a single LLM API request.

        Args:
            prompt: User-role payload (per-function evidence).
            system_prompt: Optional system-role addendum (framework
                template). When provided the request shape becomes
                ``[system: preamble + system_prompt, user: prompt]``.

        Returns:
            LLM response content

        Raises:
            Exception: If API call fails
        """
        try:
            # Compose the system message. When the caller provides the
            # framework template via ``system_prompt`` we concat it after
            # the short security-expert preamble so models see the
            # response-format expectations *before* the lengthy template.
            # When ``system_prompt`` is None we keep the legacy single
            # short system message — preserves behaviour for any caller
            # that hasn't migrated to the build_prompt_parts API yet.
            if system_prompt:
                system_content = f"{self._BASE_SYSTEM_PREAMBLE}\n\n{system_prompt}"
            else:
                system_content = self._BASE_SYSTEM_PREAMBLE

            request_params = {
                "model": self._model,
                "messages": [
                    {"role": "system", "content": system_content},
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

            # Native JSON mode is OpenAI/Azure-only. Bedrock Anthropic in
            # particular returns ``{}`` when the flag is set alongside a
            # multi-KB system prompt; rely on the system-message
            # instruction instead. See _supports_native_json_mode docs.
            if self._supports_native_json_mode():
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
