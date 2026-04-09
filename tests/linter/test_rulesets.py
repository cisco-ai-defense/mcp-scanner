# Copyright 2026 Cisco Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
"""Tests for ruleset configuration and YAML overrides."""

import pytest

from mcpscanner.core.analyzers.linter.finding import LintSeverity
from mcpscanner.core.analyzers.linter.rulesets import build_registry, QUALITY_RULE_IDS
from mcpscanner.core.analyzers.linter.rules import ALL_RULES
from mcpscanner.core.analyzers.linter.config import LintConfig


class TestBuildRegistry:
    def test_recommended_loads_all(self):
        reg = build_registry("recommended")
        assert reg.total_rules == 37
        assert reg.active_count == 37

    def test_strict_promotes_info_to_warning(self):
        reg = build_registry("strict")
        for rule in reg.get_active_rules():
            assert rule.severity in (LintSeverity.ERROR, LintSeverity.WARNING)

    def test_quality_disables_non_doc_rules(self):
        reg = build_registry("quality")
        active_ids = {r.id for r in reg.get_active_rules()}
        assert active_ids.issubset(QUALITY_RULE_IDS)

    def test_quality_keeps_doc_rules(self):
        reg = build_registry("quality")
        active_ids = {r.id for r in reg.get_active_rules()}
        assert "tool-has-description" in active_ids
        assert "tool-schema-has-examples" in active_ids

    def test_override_disable(self):
        reg = build_registry("recommended", overrides={"tool-has-name": "off"})
        active_ids = {r.id for r in reg.get_active_rules()}
        assert "tool-has-name" not in active_ids

    def test_override_severity(self):
        reg = build_registry("recommended", overrides={"tool-output-schema-defined": "warning"})
        rule = reg.get_rule("tool-output-schema-defined")
        # Re-fetch via active rules to ensure override applied
        for r in reg.get_active_rules():
            if r.id == "tool-output-schema-defined":
                assert r.severity == LintSeverity.WARNING

    def test_override_invalid_severity_ignored(self):
        reg = build_registry("recommended", overrides={"tool-has-name": "critical"})
        active_ids = {r.id for r in reg.get_active_rules()}
        assert "tool-has-name" in active_ids


class TestLintConfig:
    def test_default(self):
        cfg = LintConfig.default()
        assert cfg.extends == "recommended"
        assert cfg.rules == {}

    def test_load_nonexistent_file(self):
        cfg = LintConfig.from_file("/nonexistent/path.yaml")
        assert cfg.extends == "recommended"

    def test_load_none(self):
        cfg = LintConfig.load(None)
        assert cfg.extends == "recommended"


class TestRuleRegistryOperations:
    def test_register_and_get(self):
        reg = build_registry()
        rule = reg.get_rule("tool-has-name")
        assert rule is not None
        assert rule.id == "tool-has-name"

    def test_disable_enable(self):
        reg = build_registry()
        reg.disable("tool-has-name")
        active_ids = {r.id for r in reg.get_active_rules()}
        assert "tool-has-name" not in active_ids
        reg.enable("tool-has-name")
        active_ids = {r.id for r in reg.get_active_rules()}
        assert "tool-has-name" in active_ids

    def test_get_active_by_category(self):
        reg = build_registry()
        tool_rules = reg.get_active_rules(category="tool")
        assert all(r.category == "tool" for r in tool_rules)
        prompt_rules = reg.get_active_rules(category="prompt")
        assert all(r.category == "prompt" for r in prompt_rules)

    def test_all_rule_ids(self):
        reg = build_registry()
        assert len(reg.all_rule_ids) == 37

    def test_get_nonexistent_rule(self):
        reg = build_registry()
        assert reg.get_rule("nonexistent") is None
