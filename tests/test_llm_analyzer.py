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

"""Tests for LLM Analyzer module."""

import pytest
import json
from unittest.mock import AsyncMock, patch, MagicMock

from mcpscanner.config import Config
from mcpscanner.core.analyzers.llm_analyzer import LLMAnalyzer
from mcpscanner.core.analyzers.base import SecurityFinding


class TestLLMPromptLoading:
    """Test cases for the prompt loading logic in LLMAnalyzer."""

    def test_init_loads_prompts_successfully(self):
        """Test that LLMAnalyzer initializes and loads prompts correctly."""
        config = Config(llm_provider_api_key="test-key")
        # This will raise an error if prompts are not found
        analyzer = LLMAnalyzer(config)
        assert analyzer._protection_rules is not None
        assert analyzer._threat_analysis_prompt is not None
        assert (
            "Core Protection Rules for LLM Security Analysis"
            in analyzer._protection_rules
        )

    @patch("mcpscanner.core.analyzers.llm_analyzer.LLMAnalyzer._load_prompt")
    def test_init_raises_file_not_found(self, mock_load_prompt):
        """Test that LLMAnalyzer raises FileNotFoundError if a prompt is missing."""
        mock_load_prompt.side_effect = FileNotFoundError("Prompt not found")
        config = Config(llm_provider_api_key="test-key")
        with pytest.raises(FileNotFoundError):
            LLMAnalyzer(config)

    @patch("mcpscanner.core.analyzers.llm_analyzer.LLMAnalyzer._load_prompt")
    def test_init_raises_io_error(self, mock_load_prompt):
        """Test that LLMAnalyzer raises IOError if a prompt cannot be read."""
        mock_load_prompt.side_effect = IOError("Cannot read prompt")
        config = Config(llm_provider_api_key="test-key")
        with pytest.raises(IOError):
            LLMAnalyzer(config)


class TestLLMAnalyzer:
    """Test cases for LLMAnalyzer class."""

    def test_init_with_valid_config(self):
        """Test LLMAnalyzer initialization with valid LLM provider API key."""
        config = Config(llm_provider_api_key="test-api-key")
        analyzer = LLMAnalyzer(config)
        assert analyzer._config == config

    def test_init_without_llm_key(self):
        """Test LLMAnalyzer initialization without LLM provider API key raises error."""
        config = Config()
        with pytest.raises(ValueError, match="LLM provider API key is required"):
            LLMAnalyzer(config)

    def test_create_threat_analysis_prompt(self):
        """Test creation of threat analysis prompt for LLM."""
        config = Config(llm_provider_api_key="test-api-key")
        analyzer = LLMAnalyzer(config)

        tool_name = "file_reader"
        description = "This tool reads files from the system"
        parameters = {"path": {"type": "string", "description": "Path to the file"}}

        prompt, prompt_injection_detected = analyzer._create_threat_analysis_prompt(
            tool_name, description, parameters
        )

        assert tool_name in prompt
        assert description in prompt
        assert prompt_injection_detected == False  # No injection in legitimate content
        # Check for randomized delimiter tags (should contain UNTRUSTED_INPUT_START with random ID)
        assert "UNTRUSTED_INPUT_START_" in prompt
        assert "UNTRUSTED_INPUT_END_" in prompt

    def test_parse_response_valid_json(self):
        """Test parsing valid JSON response from LLM."""
        config = Config(llm_provider_api_key="test-api-key")
        analyzer = LLMAnalyzer(config)

        response_content = """
        Here's my analysis:
        {
            "is_malicious": true,
            "risk_score": 85,
            "severity": "High",
            "threats_detected": [
                {
                    "type": "data_exfiltration",
                    "description": "Tool can read sensitive files",
                    "risk_level": "High"
                }
            ],
            "data_exfiltration_risk": {
                "present": true,
                "risk_level": "High",
                "description": "File system access detected"
            },
            "summary": "High risk tool with file access capabilities"
        }
        """

        result = analyzer._parse_response(response_content)

        assert result["is_malicious"] is True
        assert result["risk_score"] == 85
        assert result["severity"] == "High"
        assert len(result["threats_detected"]) == 1
        assert result["data_exfiltration_risk"]["present"] is True

    def test_parse_response_invalid_json(self):
        """Test parsing invalid JSON response."""
        config = Config(llm_provider_api_key="test-api-key")
        analyzer = LLMAnalyzer(config)

        response_content = "This tool appears malicious and dangerous with potential for data exfiltration"

        with pytest.raises(ValueError):
            analyzer._parse_response(response_content)

    def test_parse_response_empty_content(self):
        """Test parsing empty response content."""
        config = Config(llm_provider_api_key="test-api-key")
        analyzer = LLMAnalyzer(config)

        with pytest.raises(ValueError, match="Empty response from LLM"):
            analyzer._parse_response("")

    def test_create_findings_from_threat_analysis_safe_tool(self):
        """Test that no findings are created for a safe tool."""
        config = Config(llm_provider_api_key="test-api-key")
        analyzer = LLMAnalyzer(config)

        analysis = {"is_malicious": False, "risk_score": 10, "severity": "Low"}

        findings = analyzer._create_findings_from_threat_analysis(
            analysis, "safe_tool"
        )

        assert len(findings) == 0

    def test_create_findings_from_threat_analysis_malicious_tool(self):
        """Test that findings are created for a malicious tool."""
        config = Config(llm_provider_api_key="test-api-key")
        analyzer = LLMAnalyzer(config)

        analysis = {
            "threat_analysis": {
                "malicious_content_detected": True,
                "overall_risk": "HIGH",
                "primary_threats": ["DATA_EXFILTRATION", "TOOL_POISONING"],
            }
        }

        findings = analyzer._create_findings_from_threat_analysis(
            analysis, "malicious_tool"
        )

        assert len(findings) == 2

        # Check data exfiltration finding
        exfil_finding = findings[0]
        assert exfil_finding.severity == "HIGH"
        assert exfil_finding.analyzer == "LLM"
        assert exfil_finding.threat_category == "DATA_EXFILTRATION"
        assert "malicious_tool" in exfil_finding.details["tool_name"]

        # Check tool poisoning finding
        poison_finding = findings[1]
        assert poison_finding.severity == "HIGH"
        assert poison_finding.threat_category == "TOOL_POISONING"

    @pytest.mark.asyncio
    @patch("mcpscanner.core.analyzers.llm_analyzer.acompletion")
    async def test_analyze_success(self, mock_completion):
        """Test successful analysis with mocked LLM response."""
        config = Config(llm_provider_api_key="test-api-key")
        analyzer = LLMAnalyzer(config)

        # Mock the LLM response
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

        content = "This tool executes system commands"
        context = {"tool_name": "command_executor"}

        findings = await analyzer.analyze(content, context)

        assert len(findings) == 1
        assert findings[0].severity == "HIGH"
        assert findings[0].analyzer == "LLM"
        assert "command_executor" in findings[0].details["tool_name"]

        # Verify LLM API was called correctly
        mock_completion.assert_called_once()
        call_args = mock_completion.call_args
        assert (
            call_args[1]["model"] == analyzer._model
        )  # Use actual model from analyzer
        assert call_args[1]["temperature"] == 0.1
        assert len(call_args[1]["messages"]) == 2

    @pytest.mark.asyncio
    @patch("mcpscanner.core.analyzers.llm_analyzer.acompletion")
    async def test_analyze_api_failure(self, mock_completion):
        """Test analysis when LLM API fails."""
        config = Config(llm_provider_api_key="test-api-key")
        analyzer = LLMAnalyzer(config)

        # Mock API failure
        mock_completion.side_effect = Exception("API rate limit exceeded")

        content = "Test content"
        context = {"tool_name": "test_tool"}

        findings = await analyzer.analyze(content, context)

        assert len(findings) == 0

    @pytest.mark.asyncio
    @patch("mcpscanner.core.analyzers.llm_analyzer.acompletion")
    async def test_analyze_without_context(self, mock_completion):
        """Test analysis without context parameter."""
        config = Config(llm_provider_api_key="test-api-key")
        analyzer = LLMAnalyzer(config)

        # Mock safe response
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

        content = "This tool adds two numbers"

        findings = await analyzer.analyze(content)

        assert len(findings) == 0  # No security findings for safe tool

        # Verify the prompt included "Unknown Tool" as default
        call_args = mock_completion.call_args
        prompt_content = call_args[1]["messages"][1]["content"]
        assert "Unknown Tool" in prompt_content

    def test_model_configuration(self):
        """Test that the analyzer uses correct model configuration."""
        config = Config(llm_provider_api_key="test-api-key")
        analyzer = LLMAnalyzer(config)

        # Test that analyzer has the expected model from config (don't hardcode expected value)
        assert analyzer._model == config.llm_model
        assert analyzer._max_tokens == 1000
        assert analyzer._temperature == 0.1

    @pytest.mark.asyncio
    @patch("mcpscanner.core.analyzers.llm_analyzer.acompletion")
    async def test_comprehensive_threat_detection(self, mock_completion):
        """Test comprehensive threat detection with multiple threat types."""
        config = Config(llm_provider_api_key="test-api-key")
        analyzer = LLMAnalyzer(config)

        # Mock response with multiple threats
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = json.dumps(
            {
                "threat_analysis": {
                    "malicious_content_detected": True,
                    "overall_risk": "CRITICAL",
                    "primary_threats": ["PROMPT_INJECTION", "DATA_EXFILTRATION"],
                }
            }
        )
        mock_completion.return_value = mock_response

        content = "Tool that executes commands and reads files"
        context = {"tool_name": "dangerous_tool"}

        findings = await analyzer.analyze(content, context)

        assert len(findings) == 2

        # Check that all finding types are present
        threat_categories = {v.threat_category for v in findings}
        assert "PROMPT_INJECTION" in threat_categories
        assert "DATA_EXFILTRATION" in threat_categories

        # Check severity distribution
        severities = {v.severity for v in findings}
        assert (
            "UNKNOWN" in severities
        )  # CRITICAL is not in severity map, defaults to UNKNOWN
