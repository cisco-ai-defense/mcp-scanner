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

"""Unit tests for API analyzer module."""

import pytest
import httpx
import respx
from unittest.mock import patch, AsyncMock
from typing import Dict, Any

from mcpscanner.config.config import Config
from mcpscanner.core.analyzers.api_analyzer import ApiAnalyzer, enabled_rules
from mcpscanner.core.analyzers.base import SecurityFinding


class TestApiAnalyzer:
    """Test cases for ApiAnalyzer class."""

    @pytest.fixture
    def config(self):
        """Provide test configuration."""
        return Config(
            api_key="test_api_key", endpoint_url="https://test.api.com/api/v1"
        )

    @pytest.fixture
    def analyzer(self, config):
        """Provide ApiAnalyzer instance."""
        return ApiAnalyzer(config)

    def test_api_analyzer_initialization(self, config):
        """Test ApiAnalyzer initialization."""
        analyzer = ApiAnalyzer(config)
        assert analyzer.name == "ApiAnalyzer"
        assert analyzer._config == config

    def test_get_headers(self, analyzer):
        """Test _get_headers method."""
        headers = analyzer._get_headers()

        expected_headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-Cisco-AI-Defense-API-Key": "test_api_key",
        }

        assert headers == expected_headers

    def test_get_payload(self, analyzer):
        """Test _get_payload method."""
        content = "Test content to analyze"
        payload = analyzer._get_payload(content)

        expected_payload = {
            "messages": [{"role": "user", "content": content}],
            "config": {"enabled_rules": enabled_rules},
        }

        assert payload == expected_payload

    @respx.mock
    @pytest.mark.asyncio
    async def test_analyze_safe_content(self, analyzer):
        """Test analyze method with safe content."""
        content = "This is safe content"

        # Mock API response for safe content
        respx.post("https://test.api.com/api/v1/inspect/chat").mock(
            return_value=httpx.Response(
                200, json={"is_safe": True, "classifications": []}
            )
        )

        findings = await analyzer.analyze(content)

        assert findings == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_analyze_malicious_content(self, analyzer):
        """Test analyze method with malicious content."""
        content = "This is malicious content"

        # Mock API response for malicious content
        respx.post("https://test.api.com/api/v1/inspect/chat").mock(
            return_value=httpx.Response(
                200,
                json={
                    "is_safe": False,
                    "classifications": ["PROMPT_INJECTION", "HARASSMENT"],
                },
            )
        )

        findings = await analyzer.analyze(content)

        assert len(findings) == 2

        # Check first finding (PROMPT_INJECTION)
        assert findings[0].severity == "HIGH"
        assert findings[0].analyzer == "API"
        assert findings[0].threat_category == "PROMPT INJECTION"
        assert findings[0].details["threat_type"] == "PROMPT_INJECTION"  # Original classification
        assert "prompt injection" in findings[0].summary.lower()

        # Check second finding (HARASSMENT)
        assert findings[1].severity == "MEDIUM"
        assert findings[1].analyzer == "API"
        assert findings[1].threat_category == "SOCIAL ENGINEERING"
        assert findings[1].details["threat_type"] == "HARASSMENT"  # Original classification
        assert "harassment" in findings[1].summary.lower()

    @respx.mock
    @pytest.mark.asyncio
    async def test_analyze_with_context(self, analyzer):
        """Test analyze method with context."""
        content = "Malicious content"
        context = {"tool_name": "test_tool"}

        respx.post("https://test.api.com/api/v1/inspect/chat").mock(
            return_value=httpx.Response(
                200, json={"is_safe": False, "classifications": ["SECURITY_VIOLATION"]}
            )
        )

        findings = await analyzer.analyze(content, context)

        assert len(findings) == 1
        assert findings[0].details["tool_name"] == "test_tool"
        assert findings[0].details["threat_type"] == "SECURITY_VIOLATION"  # Original classification
        assert findings[0].threat_category == "SECURITY VIOLATION"
        assert findings[0].severity == "HIGH"

    @pytest.mark.asyncio
    async def test_analyze_empty_content(self, analyzer):
        """Test analyze method with empty content."""
        with patch.object(analyzer.logger, "warning") as mock_warning:
            findings = await analyzer.analyze("")

            assert findings == []
            mock_warning.assert_called_once_with(
                "Empty or None content provided for analysis"
            )

    @pytest.mark.asyncio
    async def test_analyze_whitespace_content(self, analyzer):
        """Test analyze method with whitespace-only content."""
        with patch.object(analyzer.logger, "warning") as mock_warning:
            findings = await analyzer.analyze("   \n\t   ")

            assert findings == []
            mock_warning.assert_called_once_with(
                "Empty or None content provided for analysis"
            )

    @respx.mock
    @pytest.mark.asyncio
    async def test_analyze_unknown_classification(self, analyzer):
        """Test analyze method with unknown classification."""
        content = "Test content"

        respx.post("https://test.api.com/api/v1/inspect/chat").mock(
            return_value=httpx.Response(
                200,
                json={"is_safe": False, "classifications": ["UNKNOWN_CLASSIFICATION"]},
            )
        )

        findings = await analyzer.analyze(content)

        assert len(findings) == 1
        # Should use default mapping
        assert findings[0].severity == "UNKNOWN"
        assert findings[0].threat_category == "N/A"

    @respx.mock
    @pytest.mark.asyncio
    async def test_analyze_all_classification_mappings(self, analyzer):
        """Test analyze method with all known classifications."""
        content = "Test content"

        classifications = [
            "SECURITY_VIOLATION",
            "PROMPT_INJECTION",
            "HARASSMENT",
            "HATE_SPEECH",
            "PROFANITY",
            "SEXUAL_CONTENT_AND_EXPLOITATION",
            "SOCIAL_DIVISION_AND_POLARIZATION",
            "VIOLENCE_AND_PUBLIC_SAFETY_THREATS",
            "CODE_DETECTION",
        ]

        respx.post("https://test.api.com/api/v1/inspect/chat").mock(
            return_value=httpx.Response(
                200, json={"is_safe": False, "classifications": classifications}
            )
        )

        findings = await analyzer.analyze(content)

        assert len(findings) == len(classifications)

        # Verify specific mappings based on actual API classifications
        # threat_type now contains original classification, threat_category contains mapped category
        finding_by_type = {f.details["threat_type"]: f for f in findings}

        # SECURITY_VIOLATION -> SECURITY VIOLATION (HIGH)
        assert finding_by_type["SECURITY_VIOLATION"].severity == "HIGH"
        assert finding_by_type["SECURITY_VIOLATION"].threat_category == "SECURITY VIOLATION"
        
        # PROMPT_INJECTION -> PROMPT INJECTION (HIGH)
        assert finding_by_type["PROMPT_INJECTION"].severity == "HIGH"
        assert finding_by_type["PROMPT_INJECTION"].threat_category == "PROMPT INJECTION"
        
        # HARASSMENT, HATE_SPEECH, PROFANITY, SOCIAL_DIVISION_AND_POLARIZATION -> SOCIAL ENGINEERING (MEDIUM)
        assert finding_by_type["HARASSMENT"].severity == "MEDIUM"
        assert finding_by_type["HARASSMENT"].threat_category == "SOCIAL ENGINEERING"
        assert finding_by_type["HATE_SPEECH"].severity == "MEDIUM"
        assert finding_by_type["HATE_SPEECH"].threat_category == "SOCIAL ENGINEERING"
        assert finding_by_type["PROFANITY"].severity == "MEDIUM"
        assert finding_by_type["PROFANITY"].threat_category == "SOCIAL ENGINEERING"
        assert finding_by_type["SOCIAL_DIVISION_AND_POLARIZATION"].severity == "MEDIUM"
        assert finding_by_type["SOCIAL_DIVISION_AND_POLARIZATION"].threat_category == "SOCIAL ENGINEERING"
        
        # SEXUAL_CONTENT_AND_EXPLOITATION, VIOLENCE_AND_PUBLIC_SAFETY_THREATS -> MALICIOUS BEHAVIOR (MEDIUM)
        assert finding_by_type["SEXUAL_CONTENT_AND_EXPLOITATION"].severity == "MEDIUM"
        assert finding_by_type["SEXUAL_CONTENT_AND_EXPLOITATION"].threat_category == "MALICIOUS BEHAVIOR"
        assert finding_by_type["VIOLENCE_AND_PUBLIC_SAFETY_THREATS"].severity == "MEDIUM"
        assert finding_by_type["VIOLENCE_AND_PUBLIC_SAFETY_THREATS"].threat_category == "MALICIOUS BEHAVIOR"
        
        # CODE_DETECTION -> SUSPICIOUS CODE EXECUTION (LOW)
        assert finding_by_type["CODE_DETECTION"].severity == "LOW"
        assert finding_by_type["CODE_DETECTION"].threat_category == "SUSPICIOUS CODE EXECUTION"

    @respx.mock
    @pytest.mark.asyncio
    async def test_analyze_http_error(self, analyzer):
        """Test analyze method with HTTP error."""
        content = "Test content"

        respx.post("https://test.api.com/api/v1/inspect/chat").mock(
            return_value=httpx.Response(500, text="Internal Server Error")
        )

        with patch.object(analyzer.logger, "error") as mock_error:
            with pytest.raises(httpx.HTTPStatusError):
                await analyzer.analyze(content)

            mock_error.assert_called_once()
            assert "API analysis failed" in mock_error.call_args[0][0]

    @respx.mock
    @pytest.mark.asyncio
    async def test_analyze_connection_error(self, analyzer):
        """Test analyze method with connection error."""
        content = "Test content"

        respx.post("https://test.api.com/api/v1/inspect/chat").mock(
            side_effect=httpx.ConnectError("Connection failed")
        )

        with patch.object(analyzer.logger, "error") as mock_error:
            with pytest.raises(httpx.ConnectError):
                await analyzer.analyze(content)

            mock_error.assert_called_once()
            assert "API analysis failed" in mock_error.call_args[0][0]

    @respx.mock
    @pytest.mark.asyncio
    async def test_analyze_timeout_error(self, analyzer):
        """Test analyze method with timeout error."""
        content = "Test content"

        respx.post("https://test.api.com/api/v1/inspect/chat").mock(
            side_effect=httpx.TimeoutException("Request timeout")
        )

        with patch.object(analyzer.logger, "error") as mock_error:
            with pytest.raises(httpx.TimeoutException):
                await analyzer.analyze(content)

            mock_error.assert_called_once()
            assert "API analysis failed" in mock_error.call_args[0][0]

    @respx.mock
    @pytest.mark.asyncio
    async def test_analyze_malformed_response(self, analyzer):
        """Test analyze method with malformed JSON response."""
        content = "Test content"

        respx.post("https://test.api.com/api/v1/inspect/chat").mock(
            return_value=httpx.Response(200, text="Invalid JSON")
        )

        with pytest.raises(Exception):  # JSON decode error
            await analyzer.analyze(content)

    @respx.mock
    @pytest.mark.asyncio
    async def test_analyze_missing_fields_in_response(self, analyzer):
        """Test analyze method with missing fields in response."""
        content = "Test content"

        # Response missing 'classifications' field
        respx.post("https://test.api.com/api/v1/inspect/chat").mock(
            return_value=httpx.Response(
                200, json={"is_safe": False}  # Missing classifications
            )
        )

        findings = await analyzer.analyze(content)

        # Should handle missing classifications gracefully
        assert findings == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_analyze_request_payload_and_headers(self, analyzer):
        """Test that analyze method sends correct payload and headers."""
        content = "Test content"
        context = {"tool_name": "test_tool"}

        mock_request = respx.post("https://test.api.com/api/v1/inspect/chat").mock(
            return_value=httpx.Response(
                200, json={"is_safe": True, "classifications": []}
            )
        )

        await analyzer.analyze(content, context)

        # Verify request was made
        assert mock_request.called

        # Get the request that was made
        request = mock_request.calls[0].request

        # Verify headers
        assert request.headers["Content-Type"] == "application/json"
        assert request.headers["Accept"] == "application/json"
        assert request.headers["X-Cisco-AI-Defense-API-Key"] == "test_api_key"

        # Verify payload
        import json

        payload = json.loads(request.content)
        expected_payload = {
            "messages": [{"role": "user", "content": content}],
            "config": {"enabled_rules": enabled_rules},
        }
        assert payload == expected_payload

    @respx.mock
    @pytest.mark.asyncio
    async def test_analyze_finding_details(self, analyzer):
        """Test that findings contain correct details."""
        content = "Malicious content"
        context = {"tool_name": "test_tool"}

        api_response = {
            "is_safe": False,
            "classifications": ["PROMPT_INJECTION"],
            "additional_data": "test_data",
        }

        respx.post("https://test.api.com/api/v1/inspect/chat").mock(
            return_value=httpx.Response(200, json=api_response)
        )

        findings = await analyzer.analyze(content, context)

        assert len(findings) == 1
        finding = findings[0]

        # Verify finding details
        assert finding.details["tool_name"] == "test_tool"
        assert finding.details["threat_type"] == "PROMPT_INJECTION"  # Original classification
        assert (
            finding.details["evidence"] == "PROMPT_INJECTION detected in tool content"
        )
        assert finding.details["raw_response"] == api_response
        assert finding.details["content_type"] == "text"

    def test_enabled_rules_constant(self):
        """Test that enabled_rules constant is properly defined."""
        assert isinstance(enabled_rules, list)
        assert len(enabled_rules) > 0

        # Verify structure of rules
        for rule in enabled_rules:
            assert isinstance(rule, dict)
            assert "rule_name" in rule
            assert isinstance(rule["rule_name"], str)

        # Verify some expected rules are present
        rule_names = [rule["rule_name"] for rule in enabled_rules]
        assert "Prompt Injection" in rule_names
        assert "Harassment" in rule_names
        assert "Code Detection" in rule_names
