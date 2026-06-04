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

    async def verify_alignment(self, prompt: str) -> str:
        """Send alignment verification prompt to LLM with retry logic.

        Args:
            prompt: Comprehensive prompt with alignment verification evidence

        Returns:
            LLM response (JSON string)

        Raises:
            Exception: If LLM API call fails after retries
        """
        # Log prompt length for debugging
        prompt_length = len(prompt)
        self.logger.debug(f"Prompt length: {prompt_length} characters")

        # Check against configurable threshold
        if prompt_length > MCPScannerConstants.PROMPT_LENGTH_THRESHOLD:
            self.logger.warning(
                f"Large prompt detected: {prompt_length} characters "
                f"(threshold: {MCPScannerConstants.PROMPT_LENGTH_THRESHOLD}) - may be truncated by LLM"
            )

        # Retry logic with exponential backoff (configurable via constants)
        max_retries = MCPScannerConstants.LLM_MAX_RETRIES
        base_delay = MCPScannerConstants.LLM_RETRY_BASE_DELAY

        for attempt in range(max_retries):
            try:
                return await self._make_llm_request(prompt)
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

    async def _make_llm_request(self, prompt: str) -> str:
        """Make a single LLM API request.

        Args:
            prompt: Prompt to send

        Returns:
            LLM response content

        Raises:
            Exception: If API call fails
        """
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
