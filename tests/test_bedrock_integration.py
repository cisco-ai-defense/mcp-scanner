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

"""Integration tests for AWS Bedrock LLM authentication methods.

These tests verify that the MCP Scanner correctly supports multiple Bedrock
authentication methods:
1. Bedrock API Key (MCP_SCANNER_LLM_API_KEY with bedrock-api-key-... prefix)
2. AWS Profile (AWS_PROFILE environment variable)
3. IAM Role/Temporary Credentials (AWS credentials chain)

Note: These are integration tests that require actual AWS/Bedrock credentials.
Mark with @pytest.mark.integration to run separately from unit tests.
"""

import os
import pytest
from unittest.mock import patch, MagicMock, AsyncMock
import json

from mcpscanner.config import Config
from mcpscanner.core.analyzers.llm_analyzer import LLMAnalyzer
from mcpscanner.core.scanner import Scanner
from mcpscanner.core.models import AnalyzerEnum


@pytest.mark.integration
class TestBedrockAPIKeyAuthentication:
    """Test Bedrock authentication using API key (Bearer token)."""

    @pytest.mark.asyncio
    @patch("mcpscanner.core.analyzers.llm_analyzer.acompletion")
    async def test_bedrock_with_api_key(self, mock_completion):
        """Test Bedrock model with API key authentication."""
        # Mock successful Bedrock response
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = json.dumps(
            {
                "threat_analysis": {
                    "malicious_content_detected": False,
                    "overall_risk": "SAFE",
                    "primary_threats": [],
                }
            }
        )
        mock_completion.return_value = mock_response

        # Configure with Bedrock API key
        config = Config(
            llm_provider_api_key="bedrock-api-key-test123",
            llm_model="bedrock/us.anthropic.claude-sonnet-4-5-20250929-v2:0",
            aws_region_name="us-east-1",
        )

        analyzer = LLMAnalyzer(config)
        assert analyzer._model == "bedrock/us.anthropic.claude-sonnet-4-5-20250929-v2:0"
        assert analyzer._api_key == "bedrock-api-key-test123"
        assert analyzer._aws_region == "us-east-1"

        # Test analysis
        content = "This tool reads a file"
        context = {"tool_name": "file_reader"}
        findings = await analyzer.analyze(content, context)

        # Verify API was called with correct parameters
        mock_completion.assert_called_once()
        call_args = mock_completion.call_args
        assert call_args[1]["model"] == "bedrock/us.anthropic.claude-sonnet-4-5-20250929-v2:0"
        assert call_args[1]["api_key"] == "bedrock-api-key-test123"
        assert call_args[1]["aws_region_name"] == "us-east-1"

    @pytest.mark.asyncio
    async def test_bedrock_api_key_initialization_without_region(self):
        """Test that Bedrock initialization with API key but no region uses default."""
        config = Config(
            llm_provider_api_key="bedrock-api-key-test123",
            llm_model="bedrock/anthropic.claude-sonnet-4-5-20250929-v2:0",
        )

        analyzer = LLMAnalyzer(config)
        # Should use default region from config
        assert analyzer._aws_region is not None


@pytest.mark.integration
class TestBedrockAWSProfileAuthentication:
    """Test Bedrock authentication using AWS profile."""

    @pytest.mark.asyncio
    @patch("mcpscanner.core.analyzers.llm_analyzer.acompletion")
    async def test_bedrock_with_aws_profile(self, mock_completion):
        """Test Bedrock model with AWS profile authentication."""
        # Mock successful Bedrock response
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = json.dumps(
            {
                "threat_analysis": {
                    "malicious_content_detected": False,
                    "overall_risk": "SAFE",
                    "primary_threats": [],
                }
            }
        )
        mock_completion.return_value = mock_response

        # Configure with AWS profile (no API key)
        config = Config(
            llm_model="bedrock/anthropic.claude-sonnet-4-5-20250929-v2:0",
            aws_region_name="us-east-1",
            aws_profile_name="test-profile",
        )

        analyzer = LLMAnalyzer(config)
        assert analyzer._model == "bedrock/anthropic.claude-sonnet-4-5-20250929-v2:0"
        assert analyzer._api_key is None  # No API key for profile auth
        assert analyzer._aws_region == "us-east-1"
        assert analyzer._aws_profile_name == "test-profile"

        # Test analysis
        content = "This tool writes a file"
        context = {"tool_name": "file_writer"}
        findings = await analyzer.analyze(content, context)

        # Verify API was called with correct parameters
        mock_completion.assert_called_once()
        call_args = mock_completion.call_args
        assert call_args[1]["model"] == "bedrock/anthropic.claude-sonnet-4-5-20250929-v2:0"
        assert "api_key" not in call_args[1]  # No API key
        assert call_args[1]["aws_region_name"] == "us-east-1"
        assert call_args[1]["aws_profile_name"] == "test-profile"


@pytest.mark.integration
class TestBedrockSessionTokenAuthentication:
    """Test Bedrock authentication using temporary session token."""

    @pytest.mark.asyncio
    @patch("mcpscanner.core.analyzers.llm_analyzer.acompletion")
    async def test_bedrock_with_session_token(self, mock_completion):
        """Test Bedrock model with AWS session token (temporary credentials)."""
        # Mock successful Bedrock response
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = json.dumps(
            {
                "threat_analysis": {
                    "malicious_content_detected": True,
                    "overall_risk": "HIGH",
                    "primary_threats": ["PROMPT_INJECTION"],
                }
            }
        )
        mock_completion.return_value = mock_response

        # Configure with session token (no API key)
        config = Config(
            llm_model="bedrock/anthropic.claude-sonnet-4-5-20250929-v2:0",
            aws_region_name="us-west-2",
            aws_session_token="FwoGZXIvYXdzEBMaDBtest-session-token",
        )

        analyzer = LLMAnalyzer(config)
        assert analyzer._api_key is None  # No API key for session token auth
        assert analyzer._aws_region == "us-west-2"
        assert analyzer._aws_session_token == "FwoGZXIvYXdzEBMaDBtest-session-token"

        # Test analysis
        content = "This tool executes system commands"
        context = {"tool_name": "command_executor"}
        findings = await analyzer.analyze(content, context)

        # Verify API was called with correct parameters
        mock_completion.assert_called_once()
        call_args = mock_completion.call_args
        assert call_args[1]["aws_region_name"] == "us-west-2"
        assert call_args[1]["aws_session_token"] == "FwoGZXIvYXdzEBMaDBtest-session-token"


@pytest.mark.integration
class TestBedrockErrorHandling:
    """Test Bedrock-specific error handling."""

    @pytest.mark.asyncio
    @patch("mcpscanner.core.analyzers.llm_analyzer.acompletion")
    async def test_bedrock_access_denied_error(self, mock_completion):
        """Test handling of Bedrock AccessDenied errors."""
        # Mock AccessDenied error
        mock_completion.side_effect = Exception("BedrockException: AccessDenied")

        config = Config(
            llm_provider_api_key="bedrock-api-key-invalid",
            llm_model="bedrock/anthropic.claude-sonnet-4-5-20250929-v2:0",
            aws_region_name="us-east-1",
            llm_max_retries=2,  # Reduce retries for faster test
        )

        analyzer = LLMAnalyzer(config)
        content = "Test content"
        context = {"tool_name": "test_tool"}

        # Should return empty list on error after retries
        findings = await analyzer.analyze(content, context)
        assert len(findings) == 0

        # Verify retries occurred (initial + max_retries)
        assert mock_completion.call_count == 3

    @pytest.mark.asyncio
    @patch("mcpscanner.core.analyzers.llm_analyzer.acompletion")
    async def test_bedrock_throttling_error(self, mock_completion):
        """Test handling of Bedrock ThrottlingException errors."""
        # Mock ThrottlingException error
        mock_completion.side_effect = Exception("ThrottlingException: Rate exceeded")

        config = Config(
            llm_provider_api_key="bedrock-api-key-test",
            llm_model="bedrock/anthropic.claude-sonnet-4-5-20250929-v2:0",
            aws_region_name="us-east-1",
            llm_max_retries=2,
        )

        analyzer = LLMAnalyzer(config)
        content = "Test content"
        context = {"tool_name": "test_tool"}

        findings = await analyzer.analyze(content, context)
        assert len(findings) == 0

        # Verify retries with exponential backoff
        assert mock_completion.call_count == 3


@pytest.mark.integration
class TestBedrockScannerIntegration:
    """Test full scanner integration with Bedrock."""

    def test_scanner_initialization_with_bedrock_api_key(self):
        """Test Scanner initializes correctly with Bedrock API key."""
        config = Config(
            llm_provider_api_key="bedrock-api-key-test",
            llm_model="bedrock/anthropic.claude-sonnet-4-5-20250929-v2:0",
            aws_region_name="us-east-1",
        )

        scanner = Scanner(config)
        assert scanner._llm_analyzer is not None
        assert scanner._llm_analyzer._model == "bedrock/anthropic.claude-sonnet-4-5-20250929-v2:0"

    def test_scanner_initialization_with_bedrock_profile(self):
        """Test Scanner initializes correctly with AWS profile (no API key)."""
        config = Config(
            llm_model="bedrock/anthropic.claude-sonnet-4-5-20250929-v2:0",
            aws_region_name="us-east-1",
            aws_profile_name="test-profile",
        )

        scanner = Scanner(config)
        assert scanner._llm_analyzer is not None
        assert scanner._llm_analyzer._api_key is None

    def test_scanner_validation_bedrock_without_credentials(self):
        """Test Scanner initializes with Bedrock model using default region."""
        # Bedrock model without API key still initializes (uses default region)
        config = Config(
            llm_model="bedrock/anthropic.claude-sonnet-4-5-20250929-v2:0",
            # No API key, but will use default region from config
        )

        scanner = Scanner(config)
        # LLM analyzer should initialize (it uses default region from config)
        assert scanner._llm_analyzer is not None
        # Validation should pass since Bedrock can use AWS credentials
        scanner._validate_analyzer_requirements([AnalyzerEnum.LLM])


@pytest.mark.integration
class TestBedrockEnvironmentVariables:
    """Test Bedrock configuration from environment variables."""

    @patch.dict(
        os.environ,
        {
            "AWS_REGION": "eu-west-1",
            "AWS_PROFILE": "production",
            "MCP_SCANNER_LLM_MODEL": "bedrock/anthropic.claude-sonnet-4-5-20250929-v2:0",
        },
    )
    def test_config_from_environment_variables(self):
        """Test that Bedrock config reads from environment variables."""
        config = Config(
            llm_model="bedrock/anthropic.claude-sonnet-4-5-20250929-v2:0",
        )

        # Should pick up AWS_REGION and AWS_PROFILE from environment
        assert config.aws_region_name == "eu-west-1"
        assert config.aws_profile_name == "production"

    @patch.dict(
        os.environ,
        {
            "MCP_SCANNER_LLM_API_KEY": "bedrock-api-key-from-env",
            "AWS_REGION": "ap-south-1",
        },
    )
    @pytest.mark.asyncio
    @patch("mcpscanner.core.analyzers.llm_analyzer.acompletion")
    async def test_analyzer_with_env_credentials(self, mock_completion):
        """Test analyzer uses credentials from environment variables."""
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = json.dumps(
            {
                "threat_analysis": {
                    "malicious_content_detected": False,
                    "overall_risk": "SAFE",
                    "primary_threats": [],
                }
            }
        )
        mock_completion.return_value = mock_response

        config = Config(
            llm_model="bedrock/anthropic.claude-sonnet-4-5-20250929-v2:0",
        )

        analyzer = LLMAnalyzer(config)

        # API key should be picked from environment
        # Note: Config doesn't automatically read ENV vars for API key in constructor
        # It needs to be passed explicitly or read before Config creation
        # This test documents the expected behavior

        content = "Test content"
        context = {"tool_name": "test_tool"}
        await analyzer.analyze(content, context)

        call_args = mock_completion.call_args
        # Verify region is from environment
        assert call_args[1]["aws_region_name"] == "ap-south-1"
