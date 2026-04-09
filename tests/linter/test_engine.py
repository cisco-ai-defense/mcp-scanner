# Copyright 2026 Cisco Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
"""Tests for the LintEngine orchestrator."""

import pytest

from mcpscanner.core.analyzers.linter.engine import LintEngine
from mcpscanner.core.analyzers.linter.finding import LintSeverity


class TestLintEngineBasic:
    def test_empty_input(self):
        engine = LintEngine()
        summary = engine.lint(tools=[], prompts=[], resources=[], target="test")
        assert summary.total_findings > 0  # server-has-capabilities fires
        assert summary.target == "test"
        assert summary.tools_scanned == 0

    def test_clean_tool(self):
        engine = LintEngine()
        tool = {
            "name": "get_user",
            "description": "Fetches a user record by their unique identifier from the database.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "user_id": {"type": "string", "description": "Unique user ID", "example": "usr_123"}
                },
                "required": ["user_id"],
            },
            "outputSchema": {"type": "object"},
        }
        summary = engine.lint(tools=[tool], target="test")
        tool_findings = [f for f in summary.findings if f.category == "tool"]
        assert len(tool_findings) == 0

    def test_bad_tool_generates_findings(self):
        engine = LintEngine()
        tool = {"name": "", "description": ""}
        summary = engine.lint(tools=[tool], target="test")
        tool_findings = [f for f in summary.findings if f.category == "tool"]
        assert len(tool_findings) > 0
        rule_ids = {f.rule_id for f in tool_findings}
        assert "tool-has-name" in rule_ids

    def test_summary_counts(self):
        engine = LintEngine()
        tools = [
            {"name": "a", "description": "Good enough description for the tool"},
            {"name": "b"},
        ]
        prompts = [{"name": "p1", "description": "A prompt for testing purposes"}]
        resources = [{"name": "r1", "uri": "file://x", "description": "d", "mimeType": "text/plain"}]
        summary = engine.lint(tools=tools, prompts=prompts, resources=resources, target="t")
        assert summary.tools_scanned == 2
        assert summary.prompts_scanned == 1
        assert summary.resources_scanned == 1
        assert summary.rules_checked == 37
        assert summary.total_findings == summary.rules_failed or summary.total_findings >= summary.rules_failed

    def test_findings_sorted_by_severity(self):
        engine = LintEngine()
        tool = {"name": "", "description": ""}
        summary = engine.lint(tools=[tool], target="test")
        if len(summary.findings) > 1:
            for i in range(len(summary.findings) - 1):
                assert summary.findings[i].severity.rank <= summary.findings[i + 1].severity.rank

    def test_multiple_tools(self):
        engine = LintEngine()
        tools = [{"name": f"tool_{i}"} for i in range(5)]
        summary = engine.lint(tools=tools, target="test")
        assert summary.tools_scanned == 5

    def test_server_duplicate_names_detected(self):
        engine = LintEngine()
        tools = [{"name": "same", "description": "D" * 25}, {"name": "same", "description": "D" * 25}]
        summary = engine.lint(tools=tools, target="test")
        server_findings = [f for f in summary.findings if f.rule_id == "server-tool-names-unique"]
        assert len(server_findings) == 1


class TestLintEngineRulesets:
    def test_recommended_has_all_rules(self):
        engine = LintEngine(ruleset="recommended")
        assert engine.registry.active_count == 37

    def test_strict_promotes_info(self):
        engine = LintEngine(ruleset="strict")
        for rule in engine.registry.get_active_rules():
            assert rule.severity != LintSeverity.INFO

    def test_quality_only_doc_rules(self):
        engine = LintEngine(ruleset="quality")
        assert engine.registry.active_count < 37
        for rule in engine.registry.get_active_rules():
            assert "description" in rule.id or "example" in rule.id or "output" in rule.id or "html" in rule.id


class TestLintEngineSummary:
    def test_to_dict(self):
        engine = LintEngine()
        summary = engine.lint(tools=[{"name": "t"}], target="test")
        d = summary.to_dict()
        assert "target" in d
        assert "findings" in d
        assert isinstance(d["findings"], list)
        assert "rules_checked" in d

    def test_findings_by_severity(self):
        engine = LintEngine()
        summary = engine.lint(tools=[{"name": ""}], target="test")
        for sev_name, count in summary.findings_by_severity.items():
            assert count > 0
            actual = len([f for f in summary.findings if f.severity.value == sev_name])
            assert actual == count

    def test_findings_by_category(self):
        engine = LintEngine()
        summary = engine.lint(tools=[{"name": "t"}], prompts=[{"name": "p"}], target="test")
        for cat, count in summary.findings_by_category.items():
            actual = len([f for f in summary.findings if f.category == cat])
            assert actual == count
