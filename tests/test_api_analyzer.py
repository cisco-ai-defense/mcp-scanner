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
from mcpscanner.core.analyzers.api_analyzer import ApiAnalyzer
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
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "analyze_content",
                "arguments": {
                    "content": content
                }
            },
            "id": 1
        }

        assert payload == expected_payload

    @respx.mock
    @pytest.mark.asyncio
    async def test_analyze_safe_content(self, analyzer):
        """Test analyze method with safe content."""
        content = "This is safe content"

        # Mock API response for safe content (JSON-RPC 2.0 format)
        respx.post("https://api.inspect.aidefense.aiteam.cisco.com/api/v1/inspect/mcp").mock(
            return_value=httpx.Response(
                200, json={
                    "jsonrpc": "2.0",
                    "result": {
                        "is_safe": True,
                        "classifications": [],
                        "severity": "NONE_SEVERITY",
                        "action": "Allow"
                    },
                    "id": 1
                }
            )
        )

        findings = await analyzer.analyze(content)

        assert findings == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_analyze_malicious_content(self, analyzer):
        """Test analyze method with malicious content."""
        content = "This is malicious content"

        # Mock API response for malicious content (JSON-RPC 2.0 format)
        respx.post("https://api.inspect.aidefense.aiteam.cisco.com/api/v1/inspect/mcp").mock(
            return_value=httpx.Response(
                200,
                json={
                    "jsonrpc": "2.0",
                    "result": {
                        "is_safe": False,
                        "classifications": ["PROMPT_INJECTION", "HARASSMENT"],
                        "severity": "HIGH",
                        "action": "Block",
                        "explanation": "Detected prompt injection and harassment"
                    },
                    "id": 1
                },
            )
        )

        findings = await analyzer.analyze(content)

        assert len(findings) == 2

        # Check first finding (PROMPT_INJECTION)
        assert findings[0].severity == "HIGH"
        assert findings[0].analyzer == "API"
        assert findings[0].threat_category == "PROMPT INJECTION"
        assert (
            findings[0].details["threat_type"] == "PROMPT_INJECTION"
        )  # Original classification
        assert findings[0].details["action"] == "Block"

        # Check second finding (HARASSMENT)
        assert findings[1].severity == "HIGH"  # Uses API severity
        assert findings[1].analyzer == "API"
        assert findings[1].threat_category == "SOCIAL ENGINEERING"
        assert (
            findings[1].details["threat_type"] == "HARASSMENT"
        )  # Original classification

    @respx.mock
    @pytest.mark.asyncio
    async def test_analyze_with_context(self, analyzer):
        """Test analyze method with context."""
        content = "Malicious content"
        context = {"tool_name": "test_tool"}

        respx.post("https://api.inspect.aidefense.aiteam.cisco.com/api/v1/inspect/mcp").mock(
            return_value=httpx.Response(
                200, json={
                    "jsonrpc": "2.0",
                    "result": {
                        "is_safe": False,
                        "classifications": ["SECURITY_VIOLATION"],
                        "severity": "HIGH",
                        "action": "Block"
                    },
                    "id": 1
                }
            )
        )

        findings = await analyzer.analyze(content, context)

        assert len(findings) == 1
        assert findings[0].details["tool_name"] == "test_tool"
        assert (
            findings[0].details["threat_type"] == "SECURITY_VIOLATION"
        )  # Original classification
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

        respx.post("https://api.inspect.aidefense.aiteam.cisco.com/api/v1/inspect/mcp").mock(
            return_value=httpx.Response(
                200,
                json={
                    "jsonrpc": "2.0",
                    "result": {
                        "is_safe": False,
                        "classifications": ["UNKNOWN_CLASSIFICATION"],
                        "severity": "MEDIUM",
                        "action": "Block"
                    },
                    "id": 1
                },
            )
        )

        findings = await analyzer.analyze(content)

        assert len(findings) == 1
        # Should use API severity when available, category from mapping
        assert findings[0].severity == "MEDIUM"
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

        respx.post("https://api.inspect.aidefense.aiteam.cisco.com/api/v1/inspect/mcp").mock(
            return_value=httpx.Response(
                200, json={
                    "jsonrpc": "2.0",
                    "result": {
                        "is_safe": False,
                        "classifications": classifications,
                        "severity": "HIGH",
                        "action": "Block"
                    },
                    "id": 1
                }
            )
        )

        findings = await analyzer.analyze(content)

        assert len(findings) == len(classifications)

        # Verify specific mappings based on actual API classifications
        # threat_type now contains original classification, threat_category contains mapped category
        finding_by_type = {f.details["threat_type"]: f for f in findings}

        # All findings use API severity (HIGH) since it's provided
        # SECURITY_VIOLATION -> SECURITY VIOLATION
        assert finding_by_type["SECURITY_VIOLATION"].severity == "HIGH"
        assert (
            finding_by_type["SECURITY_VIOLATION"].threat_category
            == "SECURITY VIOLATION"
        )

        # PROMPT_INJECTION -> PROMPT INJECTION
        assert finding_by_type["PROMPT_INJECTION"].severity == "HIGH"
        assert finding_by_type["PROMPT_INJECTION"].threat_category == "PROMPT INJECTION"

        # Verify threat categories are correctly mapped
        assert finding_by_type["HARASSMENT"].threat_category == "SOCIAL ENGINEERING"
        assert finding_by_type["HATE_SPEECH"].threat_category == "SOCIAL ENGINEERING"
        assert finding_by_type["PROFANITY"].threat_category == "SOCIAL ENGINEERING"
        assert (
            finding_by_type["SOCIAL_DIVISION_AND_POLARIZATION"].threat_category
            == "SOCIAL ENGINEERING"
        )

        # SEXUAL_CONTENT_AND_EXPLOITATION, VIOLENCE_AND_PUBLIC_SAFETY_THREATS -> MALICIOUS BEHAVIOR
        assert (
            finding_by_type["SEXUAL_CONTENT_AND_EXPLOITATION"].threat_category
            == "MALICIOUS BEHAVIOR"
        )
        assert (
            finding_by_type["VIOLENCE_AND_PUBLIC_SAFETY_THREATS"].threat_category
            == "MALICIOUS BEHAVIOR"
        )

        # CODE_DETECTION -> SUSPICIOUS CODE EXECUTION
        assert (
            finding_by_type["CODE_DETECTION"].threat_category
            == "SUSPICIOUS CODE EXECUTION"
        )

    @respx.mock
    @pytest.mark.asyncio
    async def test_analyze_http_error(self, analyzer):
        """Test analyze method with HTTP error."""
        content = "Test content"

        respx.post("https://api.inspect.aidefense.aiteam.cisco.com/api/v1/inspect/mcp").mock(
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

        respx.post("https://api.inspect.aidefense.aiteam.cisco.com/api/v1/inspect/mcp").mock(
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

        respx.post("https://api.inspect.aidefense.aiteam.cisco.com/api/v1/inspect/mcp").mock(
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

        respx.post("https://api.inspect.aidefense.aiteam.cisco.com/api/v1/inspect/mcp").mock(
            return_value=httpx.Response(200, text="Invalid JSON")
        )

        with pytest.raises(Exception):  # JSON decode error
            await analyzer.analyze(content)

    @respx.mock
    @pytest.mark.asyncio
    async def test_analyze_missing_fields_in_response(self, analyzer):
        """Test analyze method with missing fields in response."""
        content = "Test content"

        # Response missing 'classifications' field in result
        respx.post("https://api.inspect.aidefense.aiteam.cisco.com/api/v1/inspect/mcp").mock(
            return_value=httpx.Response(
                200, json={
                    "jsonrpc": "2.0",
                    "result": {
                        "is_safe": False  # Missing classifications
                    },
                    "id": 1
                }
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

        mock_request = respx.post("https://api.inspect.aidefense.aiteam.cisco.com/api/v1/inspect/mcp").mock(
            return_value=httpx.Response(
                200, json={
                    "jsonrpc": "2.0",
                    "result": {
                        "is_safe": True,
                        "classifications": [],
                        "severity": "NONE_SEVERITY",
                        "action": "Allow"
                    },
                    "id": 1
                }
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

        # Verify payload (JSON-RPC 2.0 format)
        import json

        payload = json.loads(request.content)
        expected_payload = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "test_tool",
                "arguments": {
                    "content": content
                }
            },
            "id": 1
        }
        assert payload == expected_payload

    @respx.mock
    @pytest.mark.asyncio
    async def test_analyze_finding_details(self, analyzer):
        """Test that findings contain correct details."""
        content = "Malicious content"
        context = {"tool_name": "test_tool"}

        api_response = {
            "jsonrpc": "2.0",
            "result": {
                "is_safe": False,
                "classifications": ["PROMPT_INJECTION"],
                "severity": "HIGH",
                "action": "Block",
                "attack_technique": "PROMPT_INJECTION",
                "explanation": "Detected prompt injection attempt",
                "event_id": "evt-12345",
                "client_transaction_id": "txn-67890",
                "rules": [{"rule_name": "Prompt Injection", "rule_id": 102}]
            },
            "id": 1
        }

        respx.post("https://api.inspect.aidefense.aiteam.cisco.com/api/v1/inspect/mcp").mock(
            return_value=httpx.Response(200, json=api_response)
        )

        findings = await analyzer.analyze(content, context)

        assert len(findings) == 1
        finding = findings[0]

        # Verify finding details
        assert finding.details["tool_name"] == "test_tool"
        assert (
            finding.details["threat_type"] == "PROMPT_INJECTION"
        )  # Original classification
        assert (
            finding.details["evidence"] == "PROMPT_INJECTION detected in tool content"
        )
        assert finding.details["raw_response"] == api_response
        assert finding.details["content_type"] == "text"
        # Verify new MCP Inspection API fields
        assert finding.details["action"] == "Block"
        assert finding.details["attack_technique"] == "PROMPT_INJECTION"
        assert finding.details["event_id"] == "evt-12345"
        assert finding.details["client_transaction_id"] == "txn-67890"
        assert finding.details["rules"] == [{"rule_name": "Prompt Injection", "rule_id": 102}]

    @respx.mock
    @pytest.mark.asyncio
    async def test_analyze_json_rpc_error_response(self, analyzer):
        """Test that JSON-RPC error responses are handled correctly."""
        content = "Test content"

        # Mock JSON-RPC error response
        respx.post("https://api.inspect.aidefense.aiteam.cisco.com/api/v1/inspect/mcp").mock(
            return_value=httpx.Response(
                200, json={
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32600,
                        "message": "Invalid Request: invalid MCP message structure"
                    },
                    "id": None
                }
            )
        )

        with patch.object(analyzer.logger, "error") as mock_error:
            findings = await analyzer.analyze(content)

            # Should return empty findings on JSON-RPC error
            assert findings == []
            mock_error.assert_called_once()
            assert "MCP Inspection API error" in mock_error.call_args[0][0]

    def test_get_payload_for_resource(self, analyzer):
        """Test _get_payload method for resource analysis."""
        content = "Resource content to analyze"
        resource_uri = "file:///etc/passwd"
        payload = analyzer._get_payload(
            content,
            mcp_method="resources/read",
            resource_uri=resource_uri
        )

        expected_payload = {
            "jsonrpc": "2.0",
            "method": "resources/read",
            "params": {
                "uri": resource_uri,
                "content": content
            },
            "id": 1
        }

        assert payload == expected_payload

    @respx.mock
    @pytest.mark.asyncio
    async def test_analyze_resource_safe_content(self, analyzer):
        """Test analyze method with safe resource content."""
        content = "This is safe resource content"
        context = {
            "resource_uri": "file:///safe/path/file.txt",
            "resource_name": "safe_file"
        }

        # Mock API response for safe resource content
        respx.post("https://api.inspect.aidefense.aiteam.cisco.com/api/v1/inspect/mcp").mock(
            return_value=httpx.Response(
                200, json={
                    "jsonrpc": "2.0",
                    "result": {
                        "is_safe": True,
                        "classifications": [],
                        "severity": "NONE_SEVERITY",
                        "action": "Allow"
                    },
                    "id": 1
                }
            )
        )

        findings = await analyzer.analyze(content, context)

        assert findings == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_analyze_resource_malicious_content(self, analyzer):
        """Test analyze method with malicious resource content (path traversal)."""
        content = "Sensitive file content"
        context = {
            "resource_uri": "file:///etc/passwd",
            "resource_name": "passwd_file"
        }

        # Mock API response for path traversal detection
        respx.post("https://api.inspect.aidefense.aiteam.cisco.com/api/v1/inspect/mcp").mock(
            return_value=httpx.Response(
                200, json={
                    "jsonrpc": "2.0",
                    "result": {
                        "is_safe": False,
                        "classifications": ["SECURITY_VIOLATION"],
                        "severity": "HIGH",
                        "action": "Block",
                        "attack_technique": "PATH_TRAVERSAL",
                        "explanation": "Detected path traversal attempt accessing sensitive system file"
                    },
                    "id": 1
                }
            )
        )

        findings = await analyzer.analyze(content, context)

        assert len(findings) == 1
        finding = findings[0]

        # Verify resource-specific details
        assert finding.severity == "HIGH"
        assert finding.details["resource_name"] == "passwd_file"
        assert finding.details["resource_uri"] == "file:///etc/passwd"
        assert finding.details["action"] == "Block"
        assert finding.details["attack_technique"] == "PATH_TRAVERSAL"
        assert "tool_name" not in finding.details

    @respx.mock
    @pytest.mark.asyncio
    async def test_analyze_resource_pii_leakage(self, analyzer):
        """Test analyze method detecting PII in resource response."""
        content = "Customer SSN: 123-45-6789, Credit Card: 4532-1111-2222-3333"
        context = {
            "resource_uri": "https://api.example.com/customer/data",
            "resource_name": "customer_data"
        }

        # Mock API response for PII detection
        respx.post("https://api.inspect.aidefense.aiteam.cisco.com/api/v1/inspect/mcp").mock(
            return_value=httpx.Response(
                200, json={
                    "jsonrpc": "2.0",
                    "result": {
                        "is_safe": False,
                        "classifications": ["PRIVACY_VIOLATION"],
                        "severity": "HIGH",
                        "action": "Block",
                        "attack_technique": "DATA_LEAKAGE",
                        "explanation": "Detected PII data including SSN and credit card numbers",
                        "rules": [
                            {"rule_name": "PII", "rule_id": 103, "entity_types": ["SSN", "CREDIT_CARD"]}
                        ]
                    },
                    "id": 1
                }
            )
        )

        findings = await analyzer.analyze(content, context)

        assert len(findings) == 1
        finding = findings[0]

        assert finding.severity == "HIGH"
        assert finding.details["resource_uri"] == "https://api.example.com/customer/data"
        assert finding.details["attack_technique"] == "DATA_LEAKAGE"
        assert "resource" in finding.details["evidence"]

    @respx.mock
    @pytest.mark.asyncio
    async def test_analyze_resource_request_payload(self, analyzer):
        """Test that resource analysis sends correct payload."""
        content = "Resource content"
        context = {
            "resource_uri": "file:///test/path",
            "resource_name": "test_resource"
        }

        mock_request = respx.post("https://api.inspect.aidefense.aiteam.cisco.com/api/v1/inspect/mcp").mock(
            return_value=httpx.Response(
                200, json={
                    "jsonrpc": "2.0",
                    "result": {
                        "is_safe": True,
                        "classifications": [],
                        "severity": "NONE_SEVERITY",
                        "action": "Allow"
                    },
                    "id": 1
                }
            )
        )

        await analyzer.analyze(content, context)

        # Verify request was made
        assert mock_request.called

        # Get the request that was made
        request = mock_request.calls[0].request

        # Verify payload uses resources/read method
        import json
        payload = json.loads(request.content)

        assert payload["method"] == "resources/read"
        assert payload["params"]["uri"] == "file:///test/path"
        assert payload["params"]["content"] == content
