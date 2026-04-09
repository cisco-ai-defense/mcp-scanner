# Copyright 2026 Cisco Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the 6 built-in resource lint rules."""

import pytest

from mcpscanner.core.analyzers.linter.rules.resource_rules import RESOURCE_RULES

CTX = {}


def _find_rule(rule_id):
    for r in RESOURCE_RULES:
        if r.id == rule_id:
            return r
    raise ValueError(f"Rule {rule_id} not found")


class TestResourceHasName:
    RULE = _find_rule("resource-has-name")

    def test_pass(self):
        assert self.RULE.check({"name": "config", "uri": "file://config.json"}, CTX) == []

    def test_fail_empty(self):
        assert len(self.RULE.check({"name": "", "uri": "file://x"}, CTX)) == 1

    def test_fail_missing(self):
        assert len(self.RULE.check({"uri": "file://x"}, CTX)) == 1


class TestResourceHasDescription:
    RULE = _find_rule("resource-has-description")

    def test_pass(self):
        assert self.RULE.check({"name": "r", "description": "desc"}, CTX) == []

    def test_fail(self):
        assert len(self.RULE.check({"name": "r"}, CTX)) == 1


class TestResourceHasMimeType:
    RULE = _find_rule("resource-has-mime-type")

    def test_pass(self):
        assert self.RULE.check({"name": "r", "mimeType": "application/json"}, CTX) == []

    def test_fail(self):
        assert len(self.RULE.check({"name": "r"}, CTX)) == 1


class TestResourceMimeTypeValid:
    RULE = _find_rule("resource-mime-type-valid")

    def test_pass_json(self):
        assert self.RULE.check({"name": "r", "mimeType": "application/json"}, CTX) == []

    def test_pass_text(self):
        assert self.RULE.check({"name": "r", "mimeType": "text/plain"}, CTX) == []

    def test_fail_invalid(self):
        findings = self.RULE.check({"name": "r", "mimeType": "not-a-mime"}, CTX)
        assert len(findings) == 1

    def test_pass_no_mime(self):
        assert self.RULE.check({"name": "r"}, CTX) == []


class TestResourceUriValid:
    RULE = _find_rule("resource-uri-valid")

    def test_pass_file_uri(self):
        assert self.RULE.check({"name": "r", "uri": "file://config.json"}, CTX) == []

    def test_pass_https_uri(self):
        assert self.RULE.check({"name": "r", "uri": "https://example.com/data"}, CTX) == []

    def test_fail_no_scheme(self):
        findings = self.RULE.check({"name": "r", "uri": "just-a-path"}, CTX)
        assert len(findings) == 1

    def test_fail_empty(self):
        findings = self.RULE.check({"name": "r", "uri": ""}, CTX)
        assert len(findings) == 1

    def test_fail_missing(self):
        findings = self.RULE.check({"name": "r"}, CTX)
        assert len(findings) == 1


class TestResourceNameConvention:
    RULE = _find_rule("resource-name-convention")

    def test_pass_snake(self):
        assert self.RULE.check({"name": "project_config"}, CTX) == []

    def test_pass_phrase(self):
        assert self.RULE.check({"name": "Project Configuration"}, CTX) == []

    def test_fail_weird(self):
        findings = self.RULE.check({"name": "  weird  name  "}, CTX)
        assert len(findings) == 1


class TestResourceRulesCount:
    def test_total_rules(self):
        assert len(RESOURCE_RULES) == 6

    def test_unique_ids(self):
        ids = [r.id for r in RESOURCE_RULES]
        assert len(ids) == len(set(ids))

    def test_all_resource_category(self):
        assert all(r.category == "resource" for r in RESOURCE_RULES)
