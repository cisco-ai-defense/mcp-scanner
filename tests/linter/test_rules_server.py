# Copyright 2026 Cisco Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the 5 built-in server lint rules."""

import pytest

from mcpscanner.core.analyzers.linter.rules.server_rules import SERVER_RULES

CTX = {}


def _find_rule(rule_id):
    for r in SERVER_RULES:
        if r.id == rule_id:
            return r
    raise ValueError(f"Rule {rule_id} not found")


class TestServerHasCapabilities:
    RULE = _find_rule("server-has-capabilities")

    def test_pass_with_tools(self):
        assert self.RULE.check({"tools": [{"name": "t"}], "prompts": [], "resources": []}, CTX) == []

    def test_pass_with_prompts(self):
        assert self.RULE.check({"tools": [], "prompts": [{"name": "p"}], "resources": []}, CTX) == []

    def test_pass_with_resources(self):
        assert self.RULE.check({"tools": [], "prompts": [], "resources": [{"name": "r"}]}, CTX) == []

    def test_fail_empty(self):
        findings = self.RULE.check({"tools": [], "prompts": [], "resources": []}, CTX)
        assert len(findings) == 1


class TestServerToolNamesUnique:
    RULE = _find_rule("server-tool-names-unique")

    def test_pass_unique(self):
        server = {"tools": [{"name": "a"}, {"name": "b"}]}
        assert self.RULE.check(server, CTX) == []

    def test_fail_duplicate(self):
        server = {"tools": [{"name": "a"}, {"name": "a"}]}
        findings = self.RULE.check(server, CTX)
        assert len(findings) == 1
        assert "a" in findings[0].message

    def test_pass_empty(self):
        assert self.RULE.check({"tools": []}, CTX) == []


class TestServerPromptNamesUnique:
    RULE = _find_rule("server-prompt-names-unique")

    def test_pass_unique(self):
        server = {"prompts": [{"name": "a"}, {"name": "b"}]}
        assert self.RULE.check(server, CTX) == []

    def test_fail_duplicate(self):
        server = {"prompts": [{"name": "x"}, {"name": "x"}]}
        findings = self.RULE.check(server, CTX)
        assert len(findings) == 1


class TestServerResourceUrisUnique:
    RULE = _find_rule("server-resource-uris-unique")

    def test_pass_unique(self):
        server = {"resources": [{"uri": "file://a"}, {"uri": "file://b"}]}
        assert self.RULE.check(server, CTX) == []

    def test_fail_duplicate(self):
        server = {"resources": [{"uri": "file://a"}, {"uri": "file://a"}]}
        findings = self.RULE.check(server, CTX)
        assert len(findings) == 1


class TestServerNoExcessiveTools:
    RULE = _find_rule("server-no-excessive-tools")

    def test_pass_few_tools(self):
        server = {"tools": [{"name": f"t{i}"} for i in range(10)]}
        assert self.RULE.check(server, CTX) == []

    def test_fail_too_many(self):
        server = {"tools": [{"name": f"t{i}"} for i in range(101)]}
        findings = self.RULE.check(server, CTX)
        assert len(findings) == 1

    def test_pass_at_limit(self):
        server = {"tools": [{"name": f"t{i}"} for i in range(100)]}
        assert self.RULE.check(server, CTX) == []


class TestServerRulesCount:
    def test_total_rules(self):
        assert len(SERVER_RULES) == 5

    def test_unique_ids(self):
        ids = [r.id for r in SERVER_RULES]
        assert len(ids) == len(set(ids))

    def test_all_server_category(self):
        assert all(r.category == "server" for r in SERVER_RULES)
