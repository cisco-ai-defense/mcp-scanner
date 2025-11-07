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

"""Unit tests for base analyzer module."""

import pytest
from typing import Dict, Any, List
from unittest.mock import patch, MagicMock

from mcpscanner.core.analyzers.base import BaseAnalyzer, SecurityFinding


class TestSecurityFinding:
    """Test cases for SecurityFinding class."""

    def test_security_finding_initialization(self):
        """Test SecurityFinding initialization with valid parameters."""
        finding = SecurityFinding(
            severity="HIGH",
            summary="Test finding",
            analyzer="test_analyzer",
            threat_category="injection",
            details={"key": "value"},
        )

        assert finding.severity == "HIGH"
        assert finding.summary == "Test finding"
        assert finding.analyzer == "test_analyzer"
        assert finding.threat_category == "injection"
        assert finding.details == {"key": "value"}

    def test_security_finding_severity_normalization(self):
        """Test severity level normalization."""
        # Test lowercase normalization
        finding = SecurityFinding("high", "Test", "analyzer", "category")
        assert finding.severity == "HIGH"

        # Test mixed case normalization
        finding = SecurityFinding("MeDiUm", "Test", "analyzer", "category")
        assert finding.severity == "MEDIUM"

        # Test invalid severity defaults to UNKNOWN
        finding = SecurityFinding("invalid", "Test", "analyzer", "category")
        assert finding.severity == "UNKNOWN"

        # Test empty severity defaults to UNKNOWN
        finding = SecurityFinding("", "Test", "analyzer", "category")
        assert finding.severity == "UNKNOWN"

        # Test None severity defaults to UNKNOWN
        finding = SecurityFinding(None, "Test", "analyzer", "category")
        assert finding.severity == "UNKNOWN"

    def test_security_finding_default_details(self):
        """Test SecurityFinding with default details."""
        finding = SecurityFinding("HIGH", "Test", "analyzer", "category")
        assert finding.details == {}

    def test_security_finding_str_representation(self):
        """Test SecurityFinding string representation."""
        finding = SecurityFinding("HIGH", "Test finding", "test_analyzer", "injection")
        expected = "HIGH: injection - Test finding (analyzer: test_analyzer)"
        assert str(finding) == expected

    def test_normalize_level_method(self):
        """Test _normalize_level method directly."""
        finding = SecurityFinding("HIGH", "Test", "analyzer", "category")

        # Test valid level
        result = finding._normalize_level("low", ["HIGH", "MEDIUM", "LOW"], "MEDIUM")
        assert result == "LOW"

        # Test invalid level returns default
        result = finding._normalize_level(
            "invalid", ["HIGH", "MEDIUM", "LOW"], "UNKNOWN"
        )
        assert result == "UNKNOWN"

        # Test empty level returns default
        result = finding._normalize_level("", ["HIGH", "MEDIUM", "LOW"], "UNKNOWN")
        assert result == "UNKNOWN"

        # Test None level returns default
        result = finding._normalize_level(None, ["HIGH", "MEDIUM", "LOW"], "UNKNOWN")
        assert result == "UNKNOWN"


class MockAnalyzer(BaseAnalyzer):
    """Mock analyzer for testing BaseAnalyzer functionality."""

    def __init__(self, name: str = "mock_analyzer", should_fail: bool = False):
        super().__init__(name)
        self.should_fail = should_fail
        self.analyze_called = False
        self.analyze_content = None
        self.analyze_context = None

    async def analyze(
        self, content: str, context: Dict[str, Any] = None
    ) -> List[SecurityFinding]:
        """Mock analyze method."""
        self.analyze_called = True
        self.analyze_content = content
        self.analyze_context = context

        if self.should_fail:
            raise Exception("Mock analyzer failure")

        if "malicious" in content.lower():
            return [
                self.create_security_finding(
                    severity="HIGH",
                    summary="Malicious content detected",
                    threat_category="injection",
                )
            ]

        return []


class TestBaseAnalyzer:
    """Test cases for BaseAnalyzer class."""

    def test_base_analyzer_initialization(self):
        """Test BaseAnalyzer initialization."""
        analyzer = MockAnalyzer("test_analyzer")
        assert analyzer.name == "test_analyzer"
        assert analyzer.logger is not None

    def test_validate_content_valid(self):
        """Test validate_content with valid content."""
        analyzer = MockAnalyzer()
        # Should not raise any exception
        analyzer.validate_content("Valid content")

    def test_validate_content_empty(self):
        """Test validate_content with empty content."""
        analyzer = MockAnalyzer()

        with pytest.raises(ValueError, match="Content cannot be empty"):
            analyzer.validate_content("")

        with pytest.raises(ValueError, match="Content cannot be empty"):
            analyzer.validate_content("   ")  # Whitespace only

        with pytest.raises(ValueError, match="Content cannot be empty"):
            analyzer.validate_content(None)

    def test_validate_content_large(self):
        """Test validate_content with very large content."""
        analyzer = MockAnalyzer()
        large_content = "x" * 100001  # Exceeds 100KB limit

        with patch.object(analyzer.logger, "warning") as mock_warning:
            analyzer.validate_content(large_content)
            mock_warning.assert_called_once()
            assert "Content is very large" in mock_warning.call_args[0][0]

    def test_create_security_finding(self):
        """Test create_security_finding method."""
        analyzer = MockAnalyzer("test_analyzer")

        finding = analyzer.create_security_finding(
            severity="HIGH",
            summary="Test finding",
            threat_category="injection",
            confidence="HIGH",
            details={"key": "value"},
        )

        assert isinstance(finding, SecurityFinding)
        assert finding.severity == "HIGH"
        assert finding.summary == "Test finding"
        assert finding.threat_category == "injection"
        assert finding.analyzer == "test_analyzer"
        assert finding.details == {"key": "value"}

    def test_create_security_finding_defaults(self):
        """Test create_security_finding with default parameters."""
        analyzer = MockAnalyzer("test_analyzer")

        finding = analyzer.create_security_finding(
            severity="MEDIUM", summary="Test finding", threat_category="injection"
        )

        assert finding.details == {}

    @pytest.mark.asyncio
    async def test_safe_analyze_success(self):
        """Test safe_analyze with successful analysis."""
        analyzer = MockAnalyzer("test_analyzer")

        with patch.object(analyzer.logger, "debug") as mock_debug:
            findings = await analyzer.safe_analyze("malicious content")

            assert len(findings) == 1
            assert findings[0].severity == "HIGH"
            assert analyzer.analyze_called
            assert analyzer.analyze_content == "malicious content"
            mock_debug.assert_called_once()
            assert "Analysis complete" in mock_debug.call_args[0][0]

    @pytest.mark.asyncio
    async def test_safe_analyze_with_context(self):
        """Test safe_analyze with context parameter."""
        analyzer = MockAnalyzer("test_analyzer")
        context = {"tool_name": "test_tool"}

        await analyzer.safe_analyze("safe content", context)

        assert analyzer.analyze_context == context

    @pytest.mark.asyncio
    async def test_safe_analyze_validation_error(self):
        """Test safe_analyze with validation error."""
        analyzer = MockAnalyzer("test_analyzer")

        with patch.object(analyzer.logger, "error") as mock_error:
            findings = await analyzer.safe_analyze("")  # Empty content

            assert findings == []
            assert not analyzer.analyze_called
            mock_error.assert_called_once()
            assert "Analysis failed" in mock_error.call_args[0][0]

    @pytest.mark.asyncio
    async def test_safe_analyze_analyzer_failure(self):
        """Test safe_analyze with analyzer failure."""
        analyzer = MockAnalyzer("test_analyzer", should_fail=True)

        with patch.object(analyzer.logger, "error") as mock_error:
            findings = await analyzer.safe_analyze("valid content")

            assert findings == []
            assert analyzer.analyze_called
            mock_error.assert_called_once()
            assert "Analysis failed" in mock_error.call_args[0][0]

    @pytest.mark.asyncio
    async def test_safe_analyze_no_findings(self):
        """Test safe_analyze with no findings."""
        analyzer = MockAnalyzer("test_analyzer")

        with patch.object(analyzer.logger, "debug") as mock_debug:
            findings = await analyzer.safe_analyze("safe content")

            assert findings == []
            assert analyzer.analyze_called
            mock_debug.assert_called_once()
            assert "found 0 potential threats" in mock_debug.call_args[0][0]

    def test_base_analyzer_abstract_method(self):
        """Test that BaseAnalyzer cannot be instantiated directly."""
        with pytest.raises(TypeError):
            BaseAnalyzer("test")

    @pytest.mark.asyncio
    async def test_analyze_method_signature(self):
        """Test that analyze method has correct signature."""
        analyzer = MockAnalyzer("test_analyzer")

        # Test with content only
        await analyzer.analyze("test content")
        assert analyzer.analyze_content == "test content"
        assert analyzer.analyze_context is None

        # Test with content and context
        context = {"key": "value"}
        await analyzer.analyze("test content", context)
        assert analyzer.analyze_context == context

    def test_logger_naming(self):
        """Test that logger is named correctly."""
        analyzer = MockAnalyzer("custom_name")
        # Logger name should include the module and analyzer name
        assert "custom_name" in analyzer.logger.name
