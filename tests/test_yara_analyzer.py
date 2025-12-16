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

# tests/test_yara_analyzer.py

import pytest
import os
import tempfile
from unittest.mock import patch, MagicMock
from mcpscanner.core.analyzers.yara_analyzer import YaraAnalyzer
from mcpscanner.config.constants import MCPScannerConstants
import yara

# --- Helper Functions ---


def create_temp_yara_rule(content):
    """Create a temporary YARA rule file."""
    temp_dir = tempfile.mkdtemp()
    rule_path = os.path.join(temp_dir, "test_rule.yar")
    with open(rule_path, "w") as f:
        f.write(content)
    return temp_dir


# --- Test Cases ---


@pytest.mark.asyncio
async def test_yara_analyzer_initialization():
    """Test the YaraAnalyzer initialization with mocked rules."""
    with patch(
        "mcpscanner.core.analyzers.yara_analyzer.YaraAnalyzer._load_rules"
    ) as mock_load_rules:
        mock_load_rules.return_value = MagicMock()
        analyzer = YaraAnalyzer()
        assert analyzer._rules is not None


@pytest.mark.asyncio
async def test_yara_analyzer_no_matches():
    """Test the YaraAnalyzer with content that doesn't match any rules."""
    with patch(
        "mcpscanner.core.analyzers.yara_analyzer.YaraAnalyzer._load_rules"
    ) as mock_load_rules:
        # Create a mock rules object that returns no matches
        mock_rules = MagicMock()
        mock_rules.match.return_value = []
        mock_load_rules.return_value = mock_rules

        analyzer = YaraAnalyzer()
        findings = await analyzer.analyze("This is safe content")

        assert len(findings) == 0
        mock_rules.match.assert_called_once()


@pytest.mark.asyncio
async def test_yara_analyzer_with_matches():
    """Test the YaraAnalyzer with content that matches rules."""
    with patch(
        "mcpscanner.core.analyzers.yara_analyzer.YaraAnalyzer._load_rules"
    ) as mock_load_rules:
        # Create a mock match object
        mock_match = MagicMock()
        mock_match.rule = "test_rule"
        mock_match.meta = {
            "description": "Test description",
            "classification": "Test Classification",
            "threat_type": "Test Threat",
        }

        # Create a mock rules object that returns matches
        mock_rules = MagicMock()
        mock_rules.match.return_value = [mock_match]
        mock_load_rules.return_value = mock_rules

        analyzer = YaraAnalyzer()
        findings = await analyzer.analyze("This content matches a rule")

        assert len(findings) == 1
        assert (
            findings[0].severity == "UNKNOWN"
        )  # Default for unmapped threat types
        assert findings[0].summary == "Detected 1 threat: test rule"
        assert findings[0].analyzer == "YARA"
        assert findings[0].details["raw_response"]["rule"] == "test_rule"
        assert (
            findings[0].details["raw_response"]["description"]
            == "Test description"
        )


@pytest.mark.asyncio
async def test_yara_analyzer_with_context():
    """Test the YaraAnalyzer with context."""
    with patch(
        "mcpscanner.core.analyzers.yara_analyzer.YaraAnalyzer._load_rules"
    ) as mock_load_rules:
        # Create a mock match object
        mock_match = MagicMock()
        mock_match.rule = "test_rule"
        mock_match.meta = {
            "description": "Test description",
            "classification": "Test Classification",
            "threat_type": "Test Threat",
        }

        # Create a mock rules object that returns matches
        mock_rules = MagicMock()
        mock_rules.match.return_value = [mock_match]
        mock_load_rules.return_value = mock_rules

        analyzer = YaraAnalyzer()
        context = {"tool_name": "test_tool", "content_type": "parameters"}
        findings = await analyzer.analyze("This content matches a rule", context)

        assert len(findings) == 1
        assert findings[0].summary == "Detected 1 threat: test rule"
        assert findings[0].details["content_type"] == "parameters"


@pytest.mark.asyncio
async def test_yara_analyzer_empty_content():
    """Test the YaraAnalyzer with empty content."""
    with patch(
        "mcpscanner.core.analyzers.yara_analyzer.YaraAnalyzer._load_rules"
    ) as mock_load_rules:
        mock_load_rules.return_value = MagicMock()

        analyzer = YaraAnalyzer()
        findings = await analyzer.analyze("")

        assert len(findings) == 0


@pytest.mark.asyncio
async def test_yara_analyzer_exception_handling():
    """Test the YaraAnalyzer exception handling."""
    with patch(
        "mcpscanner.core.analyzers.yara_analyzer.YaraAnalyzer._load_rules"
    ) as mock_load_rules:
        # Create a mock rules object that raises an exception
        mock_rules = MagicMock()
        mock_rules.match.side_effect = Exception("Test exception")
        mock_load_rules.return_value = mock_rules

        analyzer = YaraAnalyzer()

        with pytest.raises(Exception, match="Test exception"):
            await analyzer.analyze("This will cause an error")


class TestYaraRuleLoading:
    """Test cases for the YARA rule loading logic in YaraAnalyzer."""

    def test_load_rules_from_package_data(self):
        """Test that YaraAnalyzer loads rules from the default package data."""
        # This test relies on the actual package data being present.
        analyzer = YaraAnalyzer()
        assert isinstance(analyzer._rules, yara.Rules)

    def test_load_rules_from_custom_directory(self, tmp_path):
        """Test that YaraAnalyzer can load rules from a custom directory."""
        rules_dir = tmp_path / "my_rules"
        rules_dir.mkdir()
        rule_file = rules_dir / "test_rule.yara"
        rule_file.write_text(
            'rule my_test_rule { strings: $a = "hello" condition: $a }'
        )

        analyzer = YaraAnalyzer(rules_dir=rules_dir)
        assert isinstance(analyzer._rules, yara.Rules)
        # Check if a rule was actually loaded
        assert len(list(analyzer._rules)) > 0

    def test_load_rules_invalid_directory(self):
        """Test that YaraAnalyzer raises FileNotFoundError for a non-existent directory."""
        with pytest.raises(FileNotFoundError):
            YaraAnalyzer(rules_dir="/non/existent/path")

    def test_load_rules_empty_directory(self, tmp_path):
        """Test that YaraAnalyzer raises FileNotFoundError for an empty directory."""
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        with pytest.raises(FileNotFoundError):
            YaraAnalyzer(rules_dir=empty_dir)

    def test_load_rules_with_invalid_syntax(self, tmp_path):
        """Test that YaraAnalyzer raises yara.Error for rules with syntax errors."""
        rules_dir = tmp_path / "invalid_rules"
        rules_dir.mkdir()
        rule_file = rules_dir / "invalid.yara"
        rule_file.write_text("this is not a valid yara rule")

        with pytest.raises(yara.Error):
            YaraAnalyzer(rules_dir=rules_dir)
