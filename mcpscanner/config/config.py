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

import os
from typing import List, Optional

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
        aws_region_name: str = None,
        aws_session_token: str = None,
        aws_profile_name: str = None,
        aws_bearer_token_bedrock: str = None,
        llm_timeout: float = None,
        oauth_client_id: str = None,
        oauth_client_secret: str = None,
        oauth_token_url: str = None,
        oauth_scopes: List[str] = None,
        virustotal_api_key: str = None,
        virustotal_upload_files: bool = False,
        virustotal_max_files: int = None,
        virustotal_inclusion_extensions: set = None,
        virustotal_exclusion_extensions: set = None,
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
            aws_region_name (str, optional): AWS region name for Bedrock (e.g., 'us-east-1'). Falls back to AWS_REGION or AWS_DEFAULT_REGION env vars.
            aws_session_token (str, optional): AWS session token for temporary credentials. Falls back to AWS_SESSION_TOKEN env var.
            aws_profile_name (str, optional): AWS profile name from ~/.aws/credentials. Falls back to AWS_PROFILE env var.
            aws_bearer_token_bedrock (str, optional): AWS Bedrock bearer token for API gateway authentication. Falls back to AWS_BEARER_TOKEN_BEDROCK env var.
            oauth_client_id (str, optional): OAuth client ID for authentication.
            oauth_client_secret (str, optional): OAuth client secret for authentication.
            oauth_token_url (str, optional): OAuth token URL for authentication.
            oauth_scopes (List[str], optional): OAuth scopes for authentication.
            virustotal_api_key (str, optional): VirusTotal API key for binary file scanning. Falls back to VIRUSTOTAL_API_KEY env var.
            virustotal_upload_files (bool, optional): If True, upload unknown files to VT for scanning. Defaults to False.
            virustotal_max_files (int, optional): Max files to scan per directory (0=unlimited). Defaults to 10.
            virustotal_inclusion_extensions (set, optional): Binary extensions to always include. Defaults from constants.
            virustotal_exclusion_extensions (set, optional): Text/code extensions to always exclude. Defaults from constants.
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

        # AWS Bedrock configuration with environment variable fallbacks
        self._aws_region_name = (
            aws_region_name
            or os.getenv("AWS_REGION")
            or os.getenv("AWS_DEFAULT_REGION")
            or CONSTANTS.DEFAULT_AWS_REGION
        )
        self._aws_session_token = aws_session_token or os.getenv("AWS_SESSION_TOKEN")
        self._aws_profile_name = aws_profile_name or os.getenv("AWS_PROFILE")
        self._aws_bearer_token_bedrock = aws_bearer_token_bedrock or os.getenv("AWS_BEARER_TOKEN_BEDROCK")

        self._llm_timeout = llm_timeout or CONSTANTS.DEFAULT_LLM_TIMEOUT
        self._oauth_client_id = oauth_client_id
        self._oauth_client_secret = oauth_client_secret
        self._oauth_token_url = oauth_token_url
        self._oauth_scopes = oauth_scopes

        # VirusTotal configuration with environment variable fallback via constants
        # Treat empty string as None to avoid enabling VT with a blank key
        _raw_vt_key = virustotal_api_key or os.getenv(
            CONSTANTS.ENV_VIRUSTOTAL_API_KEY
        )
        self._virustotal_api_key = _raw_vt_key if _raw_vt_key else None
        # Respect explicit enable/disable from env var (True/False).
        # If not explicitly set (None), auto-enable when API key is present.
        if CONSTANTS.VIRUSTOTAL_ENABLED is not None:
            self._virustotal_enabled = CONSTANTS.VIRUSTOTAL_ENABLED
        else:
            self._virustotal_enabled = self._virustotal_api_key is not None
        self._virustotal_upload_files = (
            virustotal_upload_files or CONSTANTS.VIRUSTOTAL_UPLOAD_FILES
        )
        self._virustotal_max_files = (
            virustotal_max_files if virustotal_max_files is not None
            else CONSTANTS.VIRUSTOTAL_MAX_FILES
        )
        self._virustotal_inclusion_extensions = (
            virustotal_inclusion_extensions or CONSTANTS.VIRUSTOTAL_INCLUSION_EXTENSIONS
        )
        self._virustotal_exclusion_extensions = (
            virustotal_exclusion_extensions or CONSTANTS.VIRUSTOTAL_EXCLUSION_EXTENSIONS
        )

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
    def aws_region_name(self) -> Optional[str]:
        """Get the AWS region name for Bedrock.

        Returns:
            Optional[str]: The AWS region name (e.g., 'us-east-1').
        """
        return self._aws_region_name

    @property
    def aws_session_token(self) -> Optional[str]:
        """Get the AWS session token for temporary credentials.

        Returns:
            Optional[str]: The AWS session token.
        """
        return self._aws_session_token

    @property
    def aws_profile_name(self) -> Optional[str]:
        """Get the AWS profile name for credentials.

        Returns:
            Optional[str]: The AWS profile name from ~/.aws/credentials.
        """
        return self._aws_profile_name

    @property
    def aws_bearer_token_bedrock(self) -> Optional[str]:
        """Get the AWS Bedrock bearer token for API gateway authentication.

        Returns:
            Optional[str]: The AWS Bedrock bearer token.
        """
        return self._aws_bearer_token_bedrock

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
    def virustotal_api_key(self) -> Optional[str]:
        """Get the VirusTotal API key.

        Returns:
            Optional[str]: The VirusTotal API key for binary file scanning.
        """
        return self._virustotal_api_key

    @property
    def virustotal_enabled(self) -> bool:
        """Get whether VirusTotal scanning is enabled.

        Enabled when VIRUSTOTAL_ENABLED=true or when a VT API key is present.

        Returns:
            bool: True if VirusTotal scanning is enabled.
        """
        return self._virustotal_enabled

    @property
    def virustotal_upload_files(self) -> bool:
        """Get whether to upload unknown files to VirusTotal.

        Returns:
            bool: True if unknown files should be uploaded for scanning.
        """
        return self._virustotal_upload_files

    @property
    def virustotal_max_files(self) -> int:
        """Get the max number of files to scan per directory.

        0 means unlimited. Override via MCP_SCANNER_VT_MAX_FILES env var.

        Returns:
            int: Maximum files to scan (default 10).
        """
        return self._virustotal_max_files

    @property
    def virustotal_inclusion_extensions(self) -> set:
        """Get the set of binary extensions to always include for VT scanning.

        Override via MCP_SCANNER_VT_INCLUSION_EXTENSIONS env var (comma-separated).

        Returns:
            set: Inclusion extensions (e.g. {".exe", ".pdf", ".zip"}).
        """
        return self._virustotal_inclusion_extensions

    @property
    def virustotal_exclusion_extensions(self) -> set:
        """Get the set of text/code extensions to always exclude from VT scanning.

        Override via MCP_SCANNER_VT_EXCLUSION_EXTENSIONS env var (comma-separated).

        Returns:
            set: Exclusion extensions (e.g. {".py", ".js", ".md"}).
        """
        return self._virustotal_exclusion_extensions

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
