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

"""Constants module for MCP Scanner SDK.

This module contains all configurable constants used throughout the MCP Scanner SDK.
These constants can be overridden via environment variables for production deployments.
"""

import os
import sys
from enum import Enum
from typing import Any, Dict, Union
from importlib.resources import files
from importlib.resources.abc import Traversable
from pathlib import Path


class SeverityLevel(str, Enum):
    """Security finding severity levels."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class MCPScannerConstants:
    """Centralized configuration for all MCP Scanner constants.

    This class provides a single place to configure all constants used throughout
    the MCP Scanner SDK. Values can be overridden via environment variables.
    """

    # API Configuration
    API_BASE_URL: str = os.getenv(
        "MCP_SCANNER_ENDPOINT",
        "https://us.api.inspect.aidefense.security.cisco.com/api/v1",
    )

    API_ENDPOINT_INSPECT_CHAT: str = os.getenv(
        "MCP_SCANNER_API_ENDPOINT_INSPECT_CHAT", "inspect/chat"
    )

    # Server Configuration
    DEFAULT_SERVER_HOST: str = os.getenv("MCP_SCANNER_DEFAULT_HOST", "127.0.0.1")
    DEFAULT_SERVER_PORT: int = int(os.getenv("MCP_SCANNER_DEFAULT_PORT", "8000"))

    # Environment Variables
    ENV_API_KEY: str = os.getenv("MCP_SCANNER_ENV_API_KEY_NAME", "MCP_SCANNER_API_KEY")
    ENV_ENDPOINT: str = os.getenv(
        "MCP_SCANNER_ENV_ENDPOINT_NAME", "MCP_SCANNER_ENDPOINT"
    )
    ENV_LLM_API_KEY: str = os.getenv(
        "MCP_SCANNER_ENV_LLM_API_KEY_NAME", "MCP_SCANNER_LLM_API_KEY"
    )
    ENV_LLM_MODEL: str = os.getenv(
        "MCP_SCANNER_ENV_LLM_MODEL_NAME", "MCP_SCANNER_LLM_MODEL"
    )
    ENV_LLM_BASE_URL: str = os.getenv(
        "MCP_SCANNER_ENV_LLM_BASE_URL_NAME", "MCP_SCANNER_LLM_BASE_URL"
    )
    ENV_LLM_API_VERSION: str = os.getenv(
        "MCP_SCANNER_ENV_LLM_API_VERSION_NAME", "MCP_SCANNER_LLM_API_VERSION"
    )

    # AWS Environment Variables
    ENV_AWS_REGION: str = os.getenv(
        "MCP_SCANNER_ENV_AWS_REGION_NAME", "AWS_REGION"
    )
    ENV_AWS_ACCESS_KEY_ID: str = os.getenv(
        "MCP_SCANNER_ENV_AWS_ACCESS_KEY_ID_NAME", "AWS_ACCESS_KEY_ID"
    )
    ENV_AWS_SECRET_ACCESS_KEY: str = os.getenv(
        "MCP_SCANNER_ENV_AWS_SECRET_ACCESS_KEY_NAME", "AWS_SECRET_ACCESS_KEY"
    )
    ENV_AWS_SESSION_TOKEN: str = os.getenv(
        "MCP_SCANNER_ENV_AWS_SESSION_TOKEN_NAME", "AWS_SESSION_TOKEN"
    )
    ENV_AWS_PROFILE: str = os.getenv(
        "MCP_SCANNER_ENV_AWS_PROFILE_NAME", "AWS_PROFILE"
    )

    # Default Configuration File Paths
    DEFAULT_ENV_FILE: str = os.getenv("MCP_SCANNER_DEFAULT_ENV_FILE", ".env")

    # Package name
    PACKAGE_NAME: str = "mcpscanner"

    # YARA Configuration
    DEFAULT_YARA_RULES_DIRECTORY: str = "data/yara_rules"
    YARA_RULES_DIRECTORY: str = os.getenv(
        "MCP_SCANNER_YARA_RULES_DIR", DEFAULT_YARA_RULES_DIRECTORY
    )
    YARA_RULES_EXTENSION: str = os.getenv("MCP_SCANNER_YARA_RULES_EXT", ".yara")

    # Prompts Configuration
    DEFAULT_PROMPTS_DIRECTORY: str = "data/prompts"

    # LLM Configuration Defaults
    DEFAULT_LLM_MODEL: str = os.getenv("MCP_SCANNER_LLM_MODEL", "gpt-4o")
    DEFAULT_LLM_MAX_TOKENS: int = int(
        os.getenv("MCP_SCANNER_DEFAULT_LLM_MAX_TOKENS", "1000")
    )
    DEFAULT_LLM_TEMPERATURE: float = float(
        os.getenv("MCP_SCANNER_DEFAULT_LLM_TEMPERATURE", "0.1")
    )
    DEFAULT_LLM_BASE_URL: str = os.getenv("MCP_SCANNER_LLM_BASE_URL", None)
    DEFAULT_LLM_API_VERSION: str = os.getenv("MCP_SCANNER_LLM_API_VERSION", None)
    DEFAULT_LLM_TIMEOUT: int = int(os.getenv("MCP_SCANNER_LLM_TIMEOUT", "30"))
    
    # LLM Prompt Configuration
    PROMPT_LENGTH_THRESHOLD: int = int(
        os.getenv("MCP_SCANNER_PROMPT_LENGTH_THRESHOLD", "75000")
    )
    LLM_MAX_RETRIES: int = int(os.getenv("MCP_SCANNER_LLM_MAX_RETRIES", "3"))
    LLM_RETRY_BASE_DELAY: float = float(os.getenv("MCP_SCANNER_LLM_RETRY_BASE_DELAY", "1.0"))
    
    # Behavioral Analyzer File Size Limits
    MAX_FILE_SIZE_BYTES: int = int(
        os.getenv("MCP_SCANNER_MAX_FILE_SIZE_BYTES", "1000000")  # 1MB default
    )
    MAX_FUNCTION_SIZE_BYTES: int = int(
        os.getenv("MCP_SCANNER_MAX_FUNCTION_SIZE_BYTES", "51200")  # 50 KB default
    )

    # AWS Configuration Defaults
    DEFAULT_AWS_REGION: str = os.getenv("AWS_REGION", "us-east-1")

    # Logging Configuration
    LOG_FORMAT: str = os.getenv(
        "MCP_SCANNER_LOG_FORMAT", "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    # API Response Configuration
    API_ERROR_MESSAGE_CONFIG: str = os.getenv(
        "MCP_SCANNER_API_ERROR_MESSAGE",
        "API key or endpoint not configured. Please set {api_key_env} and {endpoint_env} in .env file or environment variables.",
    )

    # LLM Configuration Error Messages
    LLM_ERROR_MESSAGE_CONFIG: str = os.getenv(
        "MCP_SCANNER_LLM_ERROR_MESSAGE",
        "LLM API key not configured. Please set {llm_api_key_env} in .env file or environment variables.",
    )

    LLM_MODEL_ERROR_MESSAGE_CONFIG: str = os.getenv(
        "MCP_SCANNER_LLM_MODEL_ERROR_MESSAGE",
        "LLM model not configured. Please set {llm_model_env} in .env file or environment variables.",
    )

    # Timeout Configuration
    DEFAULT_HTTP_TIMEOUT: int = int(os.getenv("MCP_SCANNER_HTTP_TIMEOUT", "30"))

    # Behavioral Analyzer Prompt Limits
    # These control how much context is included in alignment verification prompts
    BEHAVIORAL_MAX_OPERATIONS_PER_PARAM: int = int(os.getenv("MCP_SCANNER_BEHAVIORAL_MAX_OPERATIONS_PER_PARAM", "10"))
    BEHAVIORAL_MAX_FUNCTION_CALLS: int = int(os.getenv("MCP_SCANNER_BEHAVIORAL_MAX_FUNCTION_CALLS", "20"))
    BEHAVIORAL_MAX_ASSIGNMENTS: int = int(os.getenv("MCP_SCANNER_BEHAVIORAL_MAX_ASSIGNMENTS", "15"))
    BEHAVIORAL_MAX_CROSS_FILE_CALLS: int = int(os.getenv("MCP_SCANNER_BEHAVIORAL_MAX_CROSS_FILE_CALLS", "10"))
    BEHAVIORAL_MAX_REACHABLE_FILES: int = int(os.getenv("MCP_SCANNER_BEHAVIORAL_MAX_REACHABLE_FILES", "5"))
    BEHAVIORAL_MAX_CONSTANTS: int = int(os.getenv("MCP_SCANNER_BEHAVIORAL_MAX_CONSTANTS", "10"))
    BEHAVIORAL_MAX_STRING_LITERALS: int = int(os.getenv("MCP_SCANNER_BEHAVIORAL_MAX_STRING_LITERALS", "15"))
    BEHAVIORAL_MAX_REACHES_CALLS: int = int(os.getenv("MCP_SCANNER_BEHAVIORAL_MAX_REACHES_CALLS", "10"))

    # OAuth Configuration
    OAUTH_CLIENT_NAME: str = os.getenv(
        "MCP_SCANNER_OAUTH_CLIENT_NAME", "MCP Scanner Client"
    )
    OAUTH_DEFAULT_REDIRECT_URI: str = os.getenv(
        "MCP_SCANNER_OAUTH_REDIRECT_URI", "http://localhost:3000/callback"
    )
    OAUTH_DEFAULT_GRANT_TYPES: str = os.getenv(
        "MCP_SCANNER_OAUTH_GRANT_TYPES", "authorization_code,refresh_token"
    )
    OAUTH_DEFAULT_RESPONSE_TYPES: str = os.getenv(
        "MCP_SCANNER_OAUTH_RESPONSE_TYPES", "code"
    )
    OAUTH_DEFAULT_SCOPE: str = os.getenv("MCP_SCANNER_OAUTH_SCOPE", "user")

    # OAuth Environment Variables
    ENV_OAUTH_CLIENT_ID: str = os.getenv(
        "MCP_SCANNER_ENV_OAUTH_CLIENT_ID_NAME", "MCP_SCANNER_OAUTH_CLIENT_ID"
    )
    ENV_OAUTH_CLIENT_SECRET: str = os.getenv(
        "MCP_SCANNER_ENV_OAUTH_CLIENT_SECRET_NAME", "MCP_SCANNER_OAUTH_CLIENT_SECRET"
    )
    ENV_OAUTH_REDIRECT_URI: str = os.getenv(
        "MCP_SCANNER_ENV_OAUTH_REDIRECT_URI_NAME", "MCP_SCANNER_OAUTH_REDIRECT_URI"
    )

    # Platform-specific MCP client configuration paths
    @classmethod
    def get_client_paths(cls) -> Dict[str, list]:
        """Get platform-specific MCP client configuration paths.

        Returns:
            Dict[str, list]: Dictionary mapping client names to their config file paths.
        """
        if sys.platform == "linux" or sys.platform == "linux2":
            return {
                "windsurf": ["~/.codeium/windsurf/mcp_config.json"],
                "cursor": ["~/.cursor/mcp.json"],
                "vscode": ["~/.vscode/mcp.json", "~/.config/Code/User/settings.json"],
            }
        elif sys.platform == "darwin":
            return {
                "windsurf": ["~/.codeium/windsurf/mcp_config.json"],
                "cursor": ["~/.cursor/mcp.json"],
                "claude": [
                    "~/Library/Application Support/Claude/claude_desktop_config.json"
                ],
                "vscode": [
                    "~/.vscode/mcp.json",
                    "~/Library/Application Support/Code/User/settings.json",
                ],
            }
        elif sys.platform == "win32":
            return {
                "windsurf": ["~/.codeium/windsurf/mcp_config.json"],
                "cursor": ["~/.cursor/mcp.json"],
                "claude": ["~/AppData/Roaming/Claude/claude_desktop_config.json"],
                "vscode": [
                    "~/.vscode/mcp.json",
                    "~/AppData/Roaming/Code/User/settings.json",
                ],
            }
        else:
            return {}

    @classmethod
    def get_well_known_mcp_paths(cls) -> list:
        """Get all well-known MCP configuration file paths for the current platform.

        Returns:
            list: List of all possible MCP config file paths.
        """
        client_paths = cls.get_client_paths()
        return [path for client, paths in client_paths.items() for path in paths]

    @classmethod
    def get_api_error_message(cls) -> str:
        """Get the formatted API error message with current environment variable names.

        Returns:
            str: The formatted error message.
        """
        return cls.API_ERROR_MESSAGE_CONFIG.format(
            api_key_env=cls.ENV_API_KEY, endpoint_env=cls.ENV_ENDPOINT
        )

    @classmethod
    def get_llm_error_message(cls) -> str:
        """Get the formatted LLM error message with current environment variable names.

        Returns:
            str: The formatted error message.
        """
        return cls.LLM_ERROR_MESSAGE_CONFIG.format(llm_api_key_env=cls.ENV_LLM_API_KEY)

    @classmethod
    def get_llm_model_error_message(cls) -> str:
        """Get the formatted LLM model error message with current environment variable names.

        Returns:
            str: The formatted error message.
        """
        return cls.LLM_MODEL_ERROR_MESSAGE_CONFIG.format(
            llm_model_env=cls.ENV_LLM_MODEL
        )

    @classmethod
    def get_yara_rules_path(cls) -> Union[Traversable, Path]:
        """Get the full path to YARA rules directory.

        Returns:
            Union[Traversable, Path]: Returns a Traversable or Path object to the YARA rules directory.
        """
        custom_rules_dir = os.getenv("MCP_SCANNER_YARA_RULES_DIR")
        if custom_rules_dir:
            # Use custom path from environment variable
            return Path(custom_rules_dir)

        # Use default path from package data
        return files(cls.PACKAGE_NAME) / cls.DEFAULT_YARA_RULES_DIRECTORY

    @classmethod
    def get_prompts_path(cls) -> Traversable:
        """Get the full path to prompts directory.

        Returns:
            Traversable: Returns a Traversable object to the full path to the prompts directory.
        """

        return files(cls.PACKAGE_NAME) / cls.DEFAULT_PROMPTS_DIRECTORY

    @classmethod
    def get_all_constants(cls) -> Dict[str, Any]:
        """Get all constants as a dictionary for debugging/logging purposes.

        Returns:
            Dict[str, Any]: Dictionary containing all constant values.
        """
        return {
            attr: getattr(cls, attr)
            for attr in dir(cls)
            if not attr.startswith("_") and not callable(getattr(cls, attr))
        }


# Create a global instance for easy access
CONSTANTS = MCPScannerConstants()
