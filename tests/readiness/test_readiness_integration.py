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

"""Integration tests for ReadinessAnalyzer with Scanner.

Tests the integration of ReadinessAnalyzer with the Scanner class
and verifies end-to-end scanning functionality.
"""

import json
import pytest
from unittest.mock import MagicMock, AsyncMock, patch

from mcpscanner.config.config import Config
from mcpscanner.core.scanner import Scanner
from mcpscanner.core.models import AnalyzerEnum
from mcpscanner.core.analyzers.readiness import ReadinessAnalyzer


class TestReadinessAnalyzerIntegration:
    """Test ReadinessAnalyzer integration with Scanner."""

    def test_scanner_initializes_readiness_analyzer(self):
        """Scanner should always initialize ReadinessAnalyzer."""
        config = Config()
        scanner = Scanner(config)

        assert scanner._readiness_analyzer is not None
        assert isinstance(scanner._readiness_analyzer, ReadinessAnalyzer)

    def test_readiness_analyzer_no_api_key_required(self):
        """ReadinessAnalyzer should work without any API keys."""
        config = Config()
        scanner = Scanner(config)

        # Readiness analyzer should be available
        assert scanner._readiness_analyzer is not None

        # API and LLM analyzers should be None without keys
        assert scanner._api_analyzer is None
        assert scanner._llm_analyzer is None

    @pytest.mark.asyncio
    async def test_validate_readiness_analyzer_requirements(self):
        """READINESS analyzer should not require API keys."""
        config = Config()
        scanner = Scanner(config)

        # Should not raise even without API keys
        scanner._validate_analyzer_requirements([AnalyzerEnum.READINESS])

    @pytest.mark.asyncio
    async def test_validate_yara_and_readiness_no_keys(self):
        """YARA and READINESS analyzers should work without API keys."""
        config = Config()
        scanner = Scanner(config)

        # Should not raise
        scanner._validate_analyzer_requirements([
            AnalyzerEnum.YARA,
            AnalyzerEnum.READINESS
        ])

    @pytest.mark.asyncio
    async def test_validate_api_without_key_raises(self):
        """API analyzer without key should raise ValueError."""
        config = Config()
        scanner = Scanner(config)

        with pytest.raises(ValueError, match="API analyzer requested"):
            scanner._validate_analyzer_requirements([AnalyzerEnum.API])

    @pytest.mark.asyncio
    async def test_analyze_tool_with_readiness(self):
        """Test _analyze_tool includes READINESS analyzer results."""
        config = Config()
        scanner = Scanner(config)

        # Create a mock MCP tool
        mock_tool = MagicMock()
        mock_tool.name = "test_tool"
        mock_tool.description = "A test tool that does something useful"
        mock_tool.model_dump_json.return_value = json.dumps({
            "name": "test_tool",
            "description": "A test tool that does something useful",
        })

        result = await scanner._analyze_tool(
            mock_tool,
            [AnalyzerEnum.READINESS]
        )

        assert result.tool_name == "test_tool"
        assert result.status == "completed"
        assert AnalyzerEnum.READINESS in result.analyzers

        # Should have readiness findings (missing timeout, etc.)
        readiness_findings = [f for f in result.findings if f.analyzer == "READINESS"]
        assert len(readiness_findings) > 0

    @pytest.mark.asyncio
    async def test_analyze_tool_without_readiness(self):
        """Test _analyze_tool excludes READINESS when not requested."""
        config = Config()
        scanner = Scanner(config)

        # Create a mock MCP tool
        mock_tool = MagicMock()
        mock_tool.name = "test_tool"
        mock_tool.description = "A test tool that does something useful"
        mock_tool.model_dump_json.return_value = json.dumps({
            "name": "test_tool",
            "description": "A test tool that does something useful",
        })

        result = await scanner._analyze_tool(
            mock_tool,
            [AnalyzerEnum.YARA]  # Only YARA, no READINESS
        )

        # Should not have readiness findings
        readiness_findings = [f for f in result.findings if f.analyzer == "READINESS"]
        assert len(readiness_findings) == 0

    @pytest.mark.asyncio
    async def test_readiness_findings_have_correct_analyzer_name(self):
        """ReadinessAnalyzer findings should have analyzer='READINESS'."""
        config = Config()
        scanner = Scanner(config)

        mock_tool = MagicMock()
        mock_tool.name = "test_tool"
        mock_tool.description = "Short"  # Too short, triggers HEUR-009
        mock_tool.model_dump_json.return_value = json.dumps({
            "name": "test_tool",
            "description": "Short",
        })

        result = await scanner._analyze_tool(
            mock_tool,
            [AnalyzerEnum.READINESS]
        )

        for finding in result.findings:
            if "HEUR-" in str(finding.details.get("rule_id", "")):
                assert finding.analyzer == "READINESS"


class TestReadinessAnalyzerEnum:
    """Test AnalyzerEnum.READINESS integration."""

    def test_readiness_in_analyzer_enum(self):
        """READINESS should be a valid AnalyzerEnum value."""
        assert hasattr(AnalyzerEnum, "READINESS")
        assert AnalyzerEnum.READINESS.value == "readiness"

    def test_analyzer_enum_contains_readiness(self):
        """AnalyzerEnum should contain READINESS."""
        enum_values = [e.value for e in AnalyzerEnum]
        assert "readiness" in enum_values


class TestReadinessCombinedWithOtherAnalyzers:
    """Test READINESS combined with other analyzers."""

    @pytest.mark.asyncio
    async def test_yara_and_readiness_combined(self):
        """Test YARA and READINESS analyzers run together."""
        config = Config()
        scanner = Scanner(config)

        mock_tool = MagicMock()
        mock_tool.name = "test_tool"
        mock_tool.description = "A test tool that does something useful"
        mock_tool.model_dump_json.return_value = json.dumps({
            "name": "test_tool",
            "description": "A test tool that does something useful",
        })

        result = await scanner._analyze_tool(
            mock_tool,
            [AnalyzerEnum.YARA, AnalyzerEnum.READINESS]
        )

        assert AnalyzerEnum.YARA in result.analyzers
        assert AnalyzerEnum.READINESS in result.analyzers

    @pytest.mark.asyncio
    async def test_readiness_does_not_interfere_with_yara(self):
        """READINESS analyzer should not affect YARA results."""
        config = Config()
        scanner = Scanner(config)

        mock_tool = MagicMock()
        mock_tool.name = "test_tool"
        mock_tool.description = "A test tool that does something useful"
        mock_tool.model_dump_json.return_value = json.dumps({
            "name": "test_tool",
            "description": "A test tool that does something useful",
        })

        # Run with YARA only
        yara_only_result = await scanner._analyze_tool(
            mock_tool,
            [AnalyzerEnum.YARA]
        )
        yara_findings = [f for f in yara_only_result.findings if f.analyzer == "YARA"]

        # Run with YARA and READINESS
        combined_result = await scanner._analyze_tool(
            mock_tool,
            [AnalyzerEnum.YARA, AnalyzerEnum.READINESS]
        )
        combined_yara_findings = [f for f in combined_result.findings if f.analyzer == "YARA"]

        # YARA findings should be the same
        assert len(yara_findings) == len(combined_yara_findings)


class TestReadinessToolDefinitionParsing:
    """Test tool definition parsing in readiness context."""

    @pytest.mark.asyncio
    async def test_tool_definition_passed_in_context(self):
        """Tool definition should be passed to readiness analyzer in context."""
        config = Config()
        scanner = Scanner(config)

        tool_data = {
            "name": "well_configured_tool",
            "description": "A well-configured tool with all necessary fields",
            "timeout": 30000,
            "maxRetries": 3,
            "backoffMs": 1000,
        }

        mock_tool = MagicMock()
        mock_tool.name = tool_data["name"]
        mock_tool.description = tool_data["description"]
        mock_tool.model_dump_json.return_value = json.dumps(tool_data)

        result = await scanner._analyze_tool(
            mock_tool,
            [AnalyzerEnum.READINESS]
        )

        # Should not have HEUR-001 (has timeout)
        timeout_findings = [
            f for f in result.findings
            if f.details and f.details.get("rule_id") == "HEUR-001"
        ]
        assert len(timeout_findings) == 0

        # Should not have HEUR-003 (has maxRetries)
        retry_findings = [
            f for f in result.findings
            if f.details and f.details.get("rule_id") == "HEUR-003"
        ]
        assert len(retry_findings) == 0


class TestReadinessScoreInFindings:
    """Test readiness score is included in findings."""

    @pytest.mark.asyncio
    async def test_readiness_score_in_finding_details(self):
        """Each finding should include readiness_score in details."""
        analyzer = ReadinessAnalyzer()
        tool_def = {
            "name": "test_tool",
            "description": "A test tool",
        }
        content = json.dumps(tool_def)
        context = {"tool_name": "test_tool"}

        findings = await analyzer.analyze(content, context)

        # All findings should have readiness_score
        for finding in findings:
            assert "readiness_score" in finding.details
            assert "is_production_ready" in finding.details

    @pytest.mark.asyncio
    async def test_production_ready_flag(self):
        """is_production_ready should be False when score < 70 or has CRITICAL."""
        analyzer = ReadinessAnalyzer()
        tool_def = {
            "name": "delete_all",
            "description": "A",  # Very short, triggers multiple findings
            "maxRetries": -1,  # Triggers HEUR-004 (HIGH)
        }
        content = json.dumps(tool_def)
        context = {"tool_name": "delete_all"}

        findings = await analyzer.analyze(content, context)

        # Should have multiple findings
        assert len(findings) > 0

        # is_production_ready should be False
        if findings:
            assert findings[0].details["is_production_ready"] is False


class TestReadinessErrorHandling:
    """Test error handling in readiness analyzer integration."""

    @pytest.mark.asyncio
    async def test_invalid_json_handled_gracefully(self):
        """Invalid JSON should be handled gracefully as plain text."""
        analyzer = ReadinessAnalyzer()
        content = "This is not valid JSON"
        context = {"tool_name": "test_tool"}

        # Should not raise
        findings = await analyzer.analyze(content, context)

        # Should parse as description and detect issues
        assert len(findings) > 0

    @pytest.mark.asyncio
    async def test_empty_content_handled(self):
        """Empty content should be handled gracefully."""
        analyzer = ReadinessAnalyzer()
        content = ""
        context = {"tool_name": "test_tool"}

        # Should not raise
        findings = await analyzer.analyze(content, context)

        # May have findings for empty description
        assert findings is not None

    @pytest.mark.asyncio
    async def test_none_context_handled(self):
        """None context should be handled gracefully."""
        analyzer = ReadinessAnalyzer()
        tool_def = {
            "name": "test_tool",
            "description": "A test tool that does something useful",
        }
        content = json.dumps(tool_def)

        # Should not raise
        findings = await analyzer.analyze(content, None)

        assert findings is not None


class TestReadinessThreatCategories:
    """Test threat category assignments."""

    @pytest.mark.asyncio
    async def test_timeout_threat_category(self):
        """HEUR-001 and HEUR-002 should use MISSING_TIMEOUT_GUARD."""
        analyzer = ReadinessAnalyzer()
        tool_def = {"name": "test", "description": "A test tool for something useful"}
        content = json.dumps(tool_def)

        findings = await analyzer.analyze(content, {"tool_name": "test"})

        timeout_finding = None
        for f in findings:
            if f.details and f.details.get("rule_id") == "HEUR-001":
                timeout_finding = f
                break

        assert timeout_finding is not None
        assert timeout_finding.threat_category == "MISSING_TIMEOUT_GUARD"

    @pytest.mark.asyncio
    async def test_retry_threat_category(self):
        """HEUR-003 through HEUR-005 should use UNSAFE_RETRY_LOOP."""
        analyzer = ReadinessAnalyzer()
        tool_def = {
            "name": "test",
            "description": "A test tool for something useful",
            "maxRetries": -1,
        }
        content = json.dumps(tool_def)

        findings = await analyzer.analyze(content, {"tool_name": "test"})

        retry_finding = None
        for f in findings:
            if f.details and f.details.get("rule_id") == "HEUR-004":
                retry_finding = f
                break

        assert retry_finding is not None
        assert retry_finding.threat_category == "UNSAFE_RETRY_LOOP"

    @pytest.mark.asyncio
    async def test_error_schema_threat_category(self):
        """HEUR-006 through HEUR-008 should use MISSING_ERROR_SCHEMA."""
        analyzer = ReadinessAnalyzer()
        tool_def = {"name": "test", "description": "A test tool for something useful"}
        content = json.dumps(tool_def)

        findings = await analyzer.analyze(content, {"tool_name": "test"})

        error_finding = None
        for f in findings:
            if f.details and f.details.get("rule_id") == "HEUR-006":
                error_finding = f
                break

        assert error_finding is not None
        assert error_finding.threat_category == "MISSING_ERROR_SCHEMA"


class TestReadinessDefaultAnalyzers:
    """Test default analyzer configuration."""

    def test_default_analyzers_do_not_include_readiness(self):
        """Default analyzers should not include READINESS by default."""
        # READINESS is opt-in, not part of default scanning
        assert AnalyzerEnum.READINESS not in Scanner.DEFAULT_ANALYZERS

    def test_readiness_must_be_explicitly_requested(self):
        """READINESS must be explicitly included in analyzers list."""
        default_analyzers = Scanner.DEFAULT_ANALYZERS

        # Default should be API and YARA
        assert AnalyzerEnum.API in default_analyzers
        assert AnalyzerEnum.YARA in default_analyzers
        assert AnalyzerEnum.READINESS not in default_analyzers

