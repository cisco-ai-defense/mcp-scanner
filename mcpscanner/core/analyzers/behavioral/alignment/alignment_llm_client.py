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

import logging
from typing import Optional

from litellm import acompletion

from .....config.config import Config


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
        if not hasattr(config, "llm_provider_api_key") or not config.llm_provider_api_key:
            raise ValueError("LLM provider API key is required for alignment verification")
        
        # Store configuration for per-request usage
        self._api_key = config.llm_provider_api_key
        self._base_url = config.llm_base_url
        self._api_version = config.llm_api_version
        
        # Model configuration
        self._model = config.llm_model
        self._max_tokens = config.llm_max_tokens
        self._temperature = config.llm_temperature
        
        self.logger = logging.getLogger(__name__)
        self.logger.info(f"AlignmentLLMClient initialized with model: {self._model}")
    
    async def verify_alignment(self, prompt: str) -> str:
        """Send alignment verification prompt to LLM.
        
        Args:
            prompt: Comprehensive prompt with alignment verification evidence
            
        Returns:
            LLM response (JSON string)
            
        Raises:
            Exception: If LLM API call fails
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
                            "Respond only with valid JSON."
                        )
                    },
                    {"role": "user", "content": prompt}
                ],
                "max_tokens": self._max_tokens,
                "temperature": self._temperature,
                "timeout": 30.0,
                "api_key": self._api_key,
                "response_format": {"type": "json_object"},  # Enable JSON mode
            }
            
            # Add optional parameters if configured
            if self._base_url:
                request_params["api_base"] = self._base_url
            if self._api_version:
                request_params["api_version"] = self._api_version
            
            self.logger.debug(f"Sending alignment verification request to {self._model}")
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
