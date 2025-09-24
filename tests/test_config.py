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

# tests/test_config.py
import pytest
from mcpscanner import Config
from mcpscanner.config.constants import MCPScannerConstants, CONSTANTS
from importlib.resources.abc import Traversable
from pathlib import Path
from unittest.mock import patch

# --- Test Cases ---


class TestConfig:
    """Test cases for Config class."""

    def test_config_initialization_defaults(self):
        """Test Config initialization with default values."""
        config = Config()
        assert config.api_key is None
        assert (
            config.base_url
            == "https://us.api.inspect.aidefense.security.cisco.com/api/v1"
        )
        assert config.llm_provider_api_key is None
        assert config.llm_model == CONSTANTS.DEFAULT_LLM_MODEL
        assert config.llm_max_tokens == CONSTANTS.DEFAULT_LLM_MAX_TOKENS
        assert config.llm_temperature == CONSTANTS.DEFAULT_LLM_TEMPERATURE
        assert config.llm_rate_limit_delay == 1.0
        assert config.llm_max_retries == 3

    def test_config_initialization_with_api_key(self):
        """Test Config initialization with API key."""
        config = Config(api_key="test_api_key")
        assert config.api_key == "test_api_key"
        assert (
            config.base_url
            == "https://us.api.inspect.aidefense.security.cisco.com/api/v1"
        )

    def test_config_custom_endpoint(self):
        """Test Config with custom endpoint URL."""
        custom_endpoint = "https://custom.endpoint.com/api/v1"
        config = Config(api_key="test_api_key", endpoint_url=custom_endpoint)
        assert config.base_url == custom_endpoint

    def test_config_llm_parameters(self):
        """Test Config with LLM parameters."""
        config = Config(
            llm_provider_api_key="llm_key",
            llm_model="gpt-4",
            llm_max_tokens=2000,
            llm_temperature=0.5,
            llm_base_url="https://custom.llm.com",
            llm_api_version="2023-12-01",
            llm_rate_limit_delay=2.0,
            llm_max_retries=5,
        )

        assert config.llm_provider_api_key == "llm_key"
        assert config.llm_model == "gpt-4"
        assert config.llm_max_tokens == 2000
        assert config.llm_temperature == 0.5
        assert config.llm_base_url == "https://custom.llm.com"
        assert config.llm_api_version == "2023-12-01"
        assert config.llm_rate_limit_delay == 2.0
        assert config.llm_max_retries == 5

    def test_config_oauth_parameters(self):
        """Test Config with OAuth parameters."""
        config = Config(
            oauth_client_id="client_id",
            oauth_client_secret="client_secret",
            oauth_token_url="https://oauth.example.com/token",
            oauth_scopes=["read", "write"],
        )

        assert config.oauth_client_id == "client_id"
        assert config.oauth_client_secret == "client_secret"
        assert config.oauth_token_url == "https://oauth.example.com/token"
        assert config.oauth_scopes == ["read", "write"]

    def test_config_temperature_zero_handling(self):
        """Test Config handles temperature=0.0 correctly."""
        config = Config(llm_temperature=0.0)
        assert config.llm_temperature == 0.0

    def test_config_rate_limit_zero_handling(self):
        """Test Config handles rate_limit_delay=0.0 correctly."""
        config = Config(llm_rate_limit_delay=0.0)
        assert config.llm_rate_limit_delay == 0.0

    def test_config_max_retries_zero_handling(self):
        """Test Config handles max_retries=0 correctly."""
        config = Config(llm_max_retries=0)
        assert config.llm_max_retries == 0

    def test_get_api_url(self):
        """Test get_api_url method."""
        config = Config(api_key="test_api_key")
        api_url = config.get_api_url("test_endpoint")
        assert (
            api_url
            == "https://us.api.inspect.aidefense.security.cisco.com/api/v1/test_endpoint"
        )

        # Test with leading slash in endpoint
        api_url = config.get_api_url("/test_endpoint")
        assert (
            api_url
            == "https://us.api.inspect.aidefense.security.cisco.com/api/v1/test_endpoint"
        )

    def test_get_api_url_custom_base(self):
        """Test get_api_url with custom base URL."""
        config = Config(endpoint_url="https://custom.api.com/v2")
        api_url = config.get_api_url("endpoint")
        assert api_url == "https://custom.api.com/v2/endpoint"

    def test_get_api_url_empty_endpoint(self):
        """Test get_api_url with empty endpoint."""
        config = Config()
        api_url = config.get_api_url("")
        assert api_url == "https://us.api.inspect.aidefense.security.cisco.com/api/v1/"

    def test_config_all_parameters(self):
        """Test Config with all parameters set."""
        config = Config(
            api_key="api_key",
            endpoint_url="https://custom.com/api",
            llm_provider_api_key="llm_key",
            llm_model="custom-model",
            llm_max_tokens=1500,
            llm_temperature=0.7,
            llm_base_url="https://llm.custom.com",
            llm_api_version="v1",
            llm_rate_limit_delay=1.5,
            llm_max_retries=2,
            oauth_client_id="oauth_id",
            oauth_client_secret="oauth_secret",
            oauth_token_url="https://oauth.com/token",
            oauth_scopes=["scope1", "scope2"],
        )

        # Verify all properties are set correctly
        assert config.api_key == "api_key"
        assert config.base_url == "https://custom.com/api"
        assert config.llm_provider_api_key == "llm_key"
        assert config.llm_model == "custom-model"
        assert config.llm_max_tokens == 1500
        assert config.llm_temperature == 0.7
        assert config.llm_base_url == "https://llm.custom.com"
        assert config.llm_api_version == "v1"
        assert config.llm_rate_limit_delay == 1.5
        assert config.llm_max_retries == 2
        assert config.oauth_client_id == "oauth_id"
        assert config.oauth_client_secret == "oauth_secret"
        assert config.oauth_token_url == "https://oauth.com/token"
        assert config.oauth_scopes == ["scope1", "scope2"]


# --- Constants Test Cases ---


def test_get_yara_rules_path_default():
    """Test get_yara_rules_path returns a Traversable by default."""
    with patch.dict("os.environ", {}, clear=True):
        path = MCPScannerConstants.get_yara_rules_path()
        assert isinstance(path, Traversable)
        assert path.name == "yara_rules"


def test_get_yara_rules_path_custom(tmp_path):
    """Test get_yara_rules_path returns a Path when env var is set."""
    custom_dir = tmp_path / "custom_rules"
    custom_dir.mkdir()
    with patch.dict("os.environ", {"MCP_SCANNER_YARA_RULES_DIR": str(custom_dir)}):
        path = MCPScannerConstants.get_yara_rules_path()
        assert isinstance(path, Path)
        assert path == custom_dir


def test_get_prompts_path():
    """Test get_prompts_path returns a Traversable."""
    path = MCPScannerConstants.get_prompts_path()
    assert isinstance(path, Traversable)
    assert path.name == "prompts"
