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

"""Configuration module for MCP Scanner SDK.

This module contains the configuration classes for the MCP Scanner SDK.
"""

from typing import List, Optional
import os

from .constants import CONSTANTS


class Config:
    """Configuration class for the MCP Scanner SDK.

    This class holds the configuration parameters required for the MCP Scanner SDK,
    such as the API key and endpoint URL.

    Attributes:
        api_key (str): The API key for authenticating with the MCP Scanner API.
        endpoint_url (str): The API endpoint URL to use.

    Example:
        >>> from mcpscanner.config import Config
        >>> config = Config(api_key="your_api_key", endpoint_url="https://eu.api.inspect.aidefense.security.cisco.com/api/v1")
    """

    def __init__(
        self,
        api_key: str = None,
        endpoint_url: Optional[str] = None,
        llm_provider_api_key: str = None,
        llm_model: str = None,
        llm_max_tokens: int = None,
        llm_temperature: float = None,
        llm_base_url: str = None,
        llm_api_version: str = None,
        llm_rate_limit_delay: float = None,
        llm_max_retries: int = None,
        llm_timeout: float = None,
        oauth_client_id: str = None,
        oauth_client_secret: str = None,
        oauth_token_url: str = None,
        oauth_scopes: List[str] = None,
        tracing_enabled: Optional[bool] = None,
        max_concurrency_tools: Optional[int] = None,
        max_concurrency_prompts: Optional[int] = None,
        max_concurrency_resources: Optional[int] = None,
    ):
        """Initialize a new Config instance.

        Args:
            api_key (str, optional): The API key for authenticating with the Cisco AI Defense API.
            endpoint_url (Optional[str], optional): The API endpoint URL to use. Overrides the default.

            llm_provider_api_key (str, optional): API key for LLM provider (OpenAI, Anthropic, etc.).
            llm_model (str, optional): The LLM model to use for LiteLLM analyzer. Defaults from constants.
            llm_base_url (str, optional): Custom base URL for LLM API (for custom endpoints).
            llm_max_tokens (int, optional): Maximum tokens for LLM responses. Defaults from constants.
            llm_temperature (float, optional): Temperature for LLM responses (0.0-1.0). Defaults from constants.
            llm_api_version (str, optional): API version for LLM provider (if required).
            llm_rate_limit_delay (float, optional): Delay in seconds between LLM API calls. Defaults to 1.0.
            llm_max_retries (int, optional): Maximum number of retries for failed LLM API calls. Defaults to 3.
            oauth_client_id (str, optional): OAuth client ID for authentication.
            oauth_client_secret (str, optional): OAuth client secret for authentication.
            oauth_token_url (str, optional): OAuth token URL for authentication.
            oauth_scopes (List[str], optional): OAuth scopes for authentication.
        """
        self._api_key = api_key
        self._endpoint_url = endpoint_url
        self._llm_provider_api_key = llm_provider_api_key
        self._llm_model = llm_model or CONSTANTS.DEFAULT_LLM_MODEL
        self._llm_max_tokens = llm_max_tokens or CONSTANTS.DEFAULT_LLM_MAX_TOKENS
        self._llm_temperature = (
            llm_temperature
            if llm_temperature is not None
            else CONSTANTS.DEFAULT_LLM_TEMPERATURE
        )
        self._llm_base_url = llm_base_url or CONSTANTS.DEFAULT_LLM_BASE_URL
        self._llm_api_version = llm_api_version or CONSTANTS.DEFAULT_LLM_API_VERSION
        self._llm_rate_limit_delay = (
            llm_rate_limit_delay if llm_rate_limit_delay is not None else 1.0
        )
        self._llm_max_retries = llm_max_retries if llm_max_retries is not None else 3
        self._llm_timeout = llm_timeout or CONSTANTS.DEFAULT_LLM_TIMEOUT
        self._oauth_client_id = oauth_client_id
        self._oauth_client_secret = oauth_client_secret
        self._oauth_token_url = oauth_token_url
        self._oauth_scopes = oauth_scopes
        self._tracing_enabled = tracing_enabled
        # Concurrency (allow env overrides if not explicitly provided)
        self._max_concurrency_tools = (
            max_concurrency_tools
            if max_concurrency_tools is not None
            else int(os.getenv("MCP_SCANNER_MAX_CONCURRENCY_TOOLS", "8"))
        )
        self._max_concurrency_prompts = (
            max_concurrency_prompts
            if max_concurrency_prompts is not None
            else int(os.getenv("MCP_SCANNER_MAX_CONCURRENCY_PROMPTS", "8"))
        )
        self._max_concurrency_resources = (
            max_concurrency_resources
            if max_concurrency_resources is not None
            else int(os.getenv("MCP_SCANNER_MAX_CONCURRENCY_RESOURCES", "8"))
        )

        # Optional LLM concurrency (env override)
        self._max_concurrent_llm_requests = int(
            os.getenv("MCP_SCANNER_MAX_CONCURRENT_LLM", "8")
        )

        # Validate and clamp concurrency values to the range [1, 8]
        self._max_concurrency_tools = self._clamp_concurrency(self._max_concurrency_tools)
        self._max_concurrency_prompts = self._clamp_concurrency(self._max_concurrency_prompts)
        self._max_concurrency_resources = self._clamp_concurrency(self._max_concurrency_resources)
        self._max_concurrent_llm_requests = self._clamp_concurrency(self._max_concurrent_llm_requests)

    @staticmethod
    def _clamp_concurrency(value: int) -> int:
        try:
            v = int(value)
        except Exception:
            v = 8
        if v < 1:
            return 1
        if v > 8:
            return 8
        return v

    @property
    def api_key(self) -> str:
        """Get the API key.

        Returns:
            str: The API key.
        """
        return self._api_key

    @property
    def llm_provider_api_key(self) -> Optional[str]:
        """Get the LLM provider API key.

        Returns:
            Optional[str]: The LLM provider API key (OpenAI, Anthropic, Google, etc.).
        """
        return self._llm_provider_api_key

    @property
    def llm_model(self) -> str:
        """Get the LLM model name.

        Returns:
            str: The LLM model name (e.g., any LiteLLM-supported model like GPT, Claude, Gemini).
        """
        return self._llm_model

    @property
    def llm_max_tokens(self) -> int:
        """Get the maximum tokens for LLM responses.

        Returns:
            int: The maximum number of tokens.
        """
        return self._llm_max_tokens

    @property
    def llm_temperature(self) -> float:
        """Get the temperature for LLM responses.

        Returns:
            float: The temperature value (0.0-1.0).
        """
        return self._llm_temperature

    @property
    def llm_base_url(self) -> Optional[str]:
        """Get the custom base URL for LLM API.

        Returns:
            Optional[str]: The custom base URL for LLM API endpoints.
        """
        return self._llm_base_url

    @property
    def llm_api_version(self) -> Optional[str]:
        """Get the API version for LLM provider.

        Returns:
            Optional[str]: The API version string if required by the provider.
        """
        return self._llm_api_version

    @property
    def llm_rate_limit_delay(self) -> float:
        """Get the delay between LLM API calls for rate limiting.

        Returns:
            float: The delay in seconds between API calls.
        """
        return self._llm_rate_limit_delay

    @property
    def llm_max_retries(self) -> int:
        """Get the maximum number of retries for failed LLM API calls.

        Returns:
            int: The maximum number of retries.
        """
        return self._llm_max_retries

    @property
    def llm_timeout(self) -> float:
        """Get the timeout for LLM API calls.

        Returns:
            float: The timeout in seconds.
        """
        return self._llm_timeout

    @property
    def oauth_client_id(self) -> Optional[str]:
        """Get the OAuth client ID.

        Returns:
            Optional[str]: The OAuth client ID.
        """
        return self._oauth_client_id

    @property
    def oauth_client_secret(self) -> Optional[str]:
        """Get the OAuth client secret.

        Returns:
            Optional[str]: The OAuth client secret.
        """
        return self._oauth_client_secret

    @property
    def oauth_token_url(self) -> Optional[str]:
        """Get the OAuth token URL.

        Returns:
            Optional[str]: The OAuth token URL.
        """
        return self._oauth_token_url

    @property
    def oauth_scopes(self) -> Optional[List[str]]:
        """Get the OAuth scopes.

        Returns:
            Optional[List[str]]: The OAuth scopes.
        """
        return self._oauth_scopes

    @property
    def tracing_enabled(self) -> Optional[bool]:
        """Get whether tracing is enabled (optional override).

        Returns:
            Optional[bool]: True to force tracing on, False to force off, None to use env default.
        """
        return self._tracing_enabled

    @property
    def max_concurrency_tools(self) -> int:
        return self._max_concurrency_tools

    @max_concurrency_tools.setter
    def max_concurrency_tools(self, value: int) -> None:
        self._max_concurrency_tools = self._clamp_concurrency(value)

    @property
    def max_concurrency_prompts(self) -> int:
        return self._max_concurrency_prompts

    @max_concurrency_prompts.setter
    def max_concurrency_prompts(self, value: int) -> None:
        self._max_concurrency_prompts = self._clamp_concurrency(value)

    @property
    def max_concurrency_resources(self) -> int:
        return self._max_concurrency_resources

    @max_concurrency_resources.setter
    def max_concurrency_resources(self, value: int) -> None:
        self._max_concurrency_resources = self._clamp_concurrency(value)

    @property
    def max_concurrent_llm_requests(self) -> int:
        return self._max_concurrent_llm_requests

    @max_concurrent_llm_requests.setter
    def max_concurrent_llm_requests(self, value: int) -> None:
        self._max_concurrent_llm_requests = self._clamp_concurrency(value)

    @property
    def base_url(self) -> str:
        """Get the base URL for the API.

        Returns:
            str: The base URL for the API.
        """
        return self._endpoint_url or CONSTANTS.API_BASE_URL

    def get_api_url(self, suffix: str) -> str:
        """Get the full URL for a specific API endpoint.

        Args:
            suffix (str): The API suffix path (without leading slash e.g. inspect/chat).

        Returns:
            str: The full URL for the specified API endpoint.
        """
        # Remove leading slash if present
        if suffix.startswith("/"):
            suffix = suffix[1:]

        return f"{self.base_url}/{suffix}"
