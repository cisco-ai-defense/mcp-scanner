# Copyright 2026 Cisco Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
"""Tests for the lint output formatter."""

import json

import pytest

from mcpscanner.core.analyzers.linter.engine import LintEngine
from mcpscanner.core.analyzers.linter.formatter import LintFormatter


@pytest.fixture
def summary_with_findings():
    engine = LintEngine()
    tool = {"name": "", "description": ""}
    return engine.lint(tools=[tool], target="https://example.com/mcp")


@pytest.fixture
def clean_summary():
    engine = LintEngine()
    tool = {
        "name": "get_user",
        "description": "Fetches a user record by their unique identifier from the database.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "user_id": {"type": "string", "description": "ID", "example": "123"}
            },
            "required": ["user_id"],
        },
        "outputSchema": {},
    }
    return engine.lint(tools=[tool], target="clean-server")


class TestTableFormat:
    def test_contains_quality_header(self, summary_with_findings):
        fmt = LintFormatter(summary_with_findings)
        output = fmt.format_table()
        assert "Quality" in output

    def test_contains_severity(self, summary_with_findings):
        fmt = LintFormatter(summary_with_findings)
        output = fmt.format_table()
        assert "error" in output.lower() or "warning" in output.lower() or "info" in output.lower()

    def test_contains_rule_id(self, summary_with_findings):
        fmt = LintFormatter(summary_with_findings)
        output = fmt.format_table()
        assert "tool-has-name" in output

    def test_contains_summary_block(self, summary_with_findings):
        fmt = LintFormatter(summary_with_findings)
        output = fmt.format_table()
        assert "Summary" in output
        assert "Rules checked:" in output
        assert "Rules passed:" in output

    def test_contains_findings_count_line(self, summary_with_findings):
        fmt = LintFormatter(summary_with_findings)
        output = fmt.format_table()
        assert "Findings" in output
        assert "Error" in output

    def test_clean_summary_zero_findings(self, clean_summary):
        fmt = LintFormatter(clean_summary)
        output = fmt.format_table()
        assert "0 Findings" in output or clean_summary.total_findings == 0


class TestSummaryFormat:
    def test_contains_summary_header(self, summary_with_findings):
        fmt = LintFormatter(summary_with_findings)
        output = fmt.format_summary()
        assert "Summary" in output

    def test_contains_scanned(self, summary_with_findings):
        fmt = LintFormatter(summary_with_findings)
        output = fmt.format_summary()
        assert "Scanned:" in output

    def test_contains_rules_info(self, summary_with_findings):
        fmt = LintFormatter(summary_with_findings)
        output = fmt.format_summary()
        assert "Rules checked:" in output
        assert "Rules failed:" in output


class TestJsonFormat:
    def test_valid_json(self, summary_with_findings):
        fmt = LintFormatter(summary_with_findings)
        output = fmt.format_json()
        data = json.loads(output)
        assert "target" in data
        assert "findings" in data
        assert isinstance(data["findings"], list)

    def test_json_has_all_fields(self, summary_with_findings):
        fmt = LintFormatter(summary_with_findings)
        data = json.loads(fmt.format_json())
        assert data["target"] == "https://example.com/mcp"
        assert "rules_checked" in data
        assert "rules_passed" in data
        assert "total_findings" in data

    def test_json_finding_structure(self, summary_with_findings):
        fmt = LintFormatter(summary_with_findings)
        data = json.loads(fmt.format_json())
        if data["findings"]:
            f = data["findings"][0]
            assert "rule_id" in f
            assert "severity" in f
            assert "category" in f
            assert "message" in f
            assert "recommendation" in f


class TestFormatDispatch:
    def test_table(self, summary_with_findings):
        fmt = LintFormatter(summary_with_findings)
        assert "Quality" in fmt.format("table")

    def test_summary(self, summary_with_findings):
        fmt = LintFormatter(summary_with_findings)
        assert "Summary" in fmt.format("summary")

    def test_json(self, summary_with_findings):
        fmt = LintFormatter(summary_with_findings)
        json.loads(fmt.format("json"))

    def test_default_is_table(self, summary_with_findings):
        fmt = LintFormatter(summary_with_findings)
        assert fmt.format() == fmt.format("table")
