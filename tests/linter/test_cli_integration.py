# Copyright 2026 Cisco Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
"""CLI integration tests for the lint subcommand (static file mode)."""

import json
import os
from pathlib import Path

import pytest

from mcpscanner.core.analyzers.linter.engine import LintEngine
from mcpscanner.core.analyzers.linter.formatter import LintFormatter

FIXTURES = Path(__file__).parent / "fixtures"


class TestStaticFileLinting:
    def test_lint_good_tools_file(self):
        data = json.loads((FIXTURES / "good_tools.json").read_text())
        tools = data["tools"]
        engine = LintEngine()
        summary = engine.lint(tools=tools, target="good_tools.json")
        tool_findings = [f for f in summary.findings if f.category == "tool"]
        error_findings = [f for f in tool_findings if f.severity.value == "error"]
        assert len(error_findings) == 0

    def test_lint_bad_tools_file(self):
        data = json.loads((FIXTURES / "bad_tools.json").read_text())
        tools = data["tools"]
        engine = LintEngine()
        summary = engine.lint(tools=tools, target="bad_tools.json")
        rule_ids = {f.rule_id for f in summary.findings}
        assert "tool-has-name" in rule_ids
        assert "tool-required-params-defined" in rule_ids

    def test_lint_produces_json_output(self):
        data = json.loads((FIXTURES / "bad_tools.json").read_text())
        tools = data["tools"]
        engine = LintEngine()
        summary = engine.lint(tools=tools, target="test")
        fmt = LintFormatter(summary)
        output = json.loads(fmt.format_json())
        assert output["total_findings"] > 0
        assert len(output["findings"]) > 0

    def test_lint_produces_table_output(self):
        data = json.loads((FIXTURES / "bad_tools.json").read_text())
        tools = data["tools"]
        engine = LintEngine()
        summary = engine.lint(tools=tools, target="test")
        fmt = LintFormatter(summary)
        output = fmt.format_table()
        assert "tool-has-name" in output
        assert "Quality" in output

    def test_strict_ruleset_catches_more(self):
        data = json.loads((FIXTURES / "good_tools.json").read_text())
        tools = data["tools"]
        rec = LintEngine(ruleset="recommended")
        strict = LintEngine(ruleset="strict")
        rec_summary = rec.lint(tools=tools, target="test")
        strict_summary = strict.lint(tools=tools, target="test")
        # Strict should catch at least as many issues
        assert strict_summary.total_findings >= rec_summary.total_findings

    def test_quality_ruleset_filters_rules(self):
        engine = LintEngine(ruleset="quality")
        tool = {"name": "t"}
        summary = engine.lint(tools=[tool], target="test")
        for f in summary.findings:
            if f.category == "tool":
                assert "description" in f.rule_id or "example" in f.rule_id or "output" in f.rule_id or "html" in f.rule_id


class TestAnalyzerEnumRegistration:
    def test_lint_in_analyzer_enum(self):
        from mcpscanner.core.models import AnalyzerEnum
        assert AnalyzerEnum.LINT.value == "lint"

    def test_lint_engine_importable(self):
        from mcpscanner.core.analyzers import LintEngine
        assert LintEngine is not None


class TestLintFinding:
    def test_finding_to_dict(self):
        from mcpscanner.core.analyzers.linter.finding import LintFinding, LintSeverity
        f = LintFinding(
            rule_id="test-rule",
            severity=LintSeverity.WARNING,
            category="tool",
            message="msg",
            recommendation="rec",
            item_name="t",
            affected_items=2,
        )
        d = f.to_dict()
        assert d["rule_id"] == "test-rule"
        assert d["severity"] == "warning"
        assert d["affected_items"] == 2
        assert "location" not in d

    def test_finding_with_location(self):
        from mcpscanner.core.analyzers.linter.finding import LintFinding, LintSeverity
        f = LintFinding(
            rule_id="test-rule",
            severity=LintSeverity.INFO,
            category="tool",
            message="msg",
            recommendation="rec",
            location="inputSchema.properties.a",
        )
        d = f.to_dict()
        assert d["location"] == "inputSchema.properties.a"


class TestLintSeverity:
    def test_ordering(self):
        from mcpscanner.core.analyzers.linter.finding import LintSeverity
        assert LintSeverity.ERROR < LintSeverity.WARNING
        assert LintSeverity.WARNING < LintSeverity.INFO
        assert LintSeverity.INFO < LintSeverity.HINT

    def test_rank(self):
        from mcpscanner.core.analyzers.linter.finding import LintSeverity
        assert LintSeverity.ERROR.rank == 0
        assert LintSeverity.HINT.rank == 3
