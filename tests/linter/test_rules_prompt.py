# Copyright 2026 Cisco Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the 8 built-in prompt lint rules."""

import pytest

from mcpscanner.core.analyzers.linter.rules.prompt_rules import PROMPT_RULES

CTX = {}


def _find_rule(rule_id):
    for r in PROMPT_RULES:
        if r.id == rule_id:
            return r
    raise ValueError(f"Rule {rule_id} not found")


class TestPromptHasName:
    RULE = _find_rule("prompt-has-name")

    def test_pass(self):
        assert self.RULE.check({"name": "greet"}, CTX) == []

    def test_fail_empty(self):
        assert len(self.RULE.check({"name": ""}, CTX)) == 1

    def test_fail_missing(self):
        assert len(self.RULE.check({}, CTX)) == 1


class TestPromptHasDescription:
    RULE = _find_rule("prompt-has-description")

    def test_pass(self):
        assert self.RULE.check({"name": "p", "description": "Does something"}, CTX) == []

    def test_fail(self):
        assert len(self.RULE.check({"name": "p"}, CTX)) == 1


class TestPromptDescriptionMinLength:
    RULE = _find_rule("prompt-description-min-length")

    def test_pass(self):
        assert self.RULE.check({"name": "p", "description": "A" * 20}, CTX) == []

    def test_fail(self):
        assert len(self.RULE.check({"name": "p", "description": "Short"}, CTX)) == 1

    def test_pass_empty(self):
        assert self.RULE.check({"name": "p", "description": ""}, CTX) == []


class TestPromptNameConvention:
    RULE = _find_rule("prompt-name-convention")

    def test_pass_snake(self):
        assert self.RULE.check({"name": "code_review"}, CTX) == []

    def test_pass_camel(self):
        assert self.RULE.check({"name": "codeReview"}, CTX) == []

    def test_pass_kebab(self):
        assert self.RULE.check({"name": "code-review"}, CTX) == []

    def test_fail(self):
        assert len(self.RULE.check({"name": "Code Review!"}, CTX)) == 1


class TestPromptHasArguments:
    RULE = _find_rule("prompt-has-arguments")

    def test_pass_with_args(self):
        assert self.RULE.check({"name": "p", "arguments": []}, CTX) == []

    def test_fail_no_args(self):
        assert len(self.RULE.check({"name": "p"}, CTX)) == 1


class TestPromptArgumentHasDescription:
    RULE = _find_rule("prompt-argument-has-description")

    def test_pass(self):
        prompt = {"name": "p", "arguments": [{"name": "a", "description": "desc"}]}
        assert self.RULE.check(prompt, CTX) == []

    def test_fail(self):
        prompt = {"name": "p", "arguments": [{"name": "a"}]}
        findings = self.RULE.check(prompt, CTX)
        assert len(findings) == 1

    def test_multiple_missing(self):
        prompt = {"name": "p", "arguments": [{"name": "a"}, {"name": "b"}]}
        findings = self.RULE.check(prompt, CTX)
        assert findings[0].affected_items == 2


class TestPromptArgumentHasRequired:
    RULE = _find_rule("prompt-argument-has-required")

    def test_pass(self):
        prompt = {"name": "p", "arguments": [{"name": "a", "required": True}]}
        assert self.RULE.check(prompt, CTX) == []

    def test_fail(self):
        prompt = {"name": "p", "arguments": [{"name": "a"}]}
        findings = self.RULE.check(prompt, CTX)
        assert len(findings) == 1


class TestPromptNoDuplicateArguments:
    RULE = _find_rule("prompt-no-duplicate-arguments")

    def test_pass_unique(self):
        prompt = {"name": "p", "arguments": [{"name": "a"}, {"name": "b"}]}
        assert self.RULE.check(prompt, CTX) == []

    def test_fail_duplicate(self):
        prompt = {"name": "p", "arguments": [{"name": "a"}, {"name": "a"}]}
        findings = self.RULE.check(prompt, CTX)
        assert len(findings) == 1
        assert findings[0].severity.value == "error"


class TestPromptRulesCount:
    def test_total_rules(self):
        assert len(PROMPT_RULES) == 8

    def test_unique_ids(self):
        ids = [r.id for r in PROMPT_RULES]
        assert len(ids) == len(set(ids))

    def test_all_prompt_category(self):
        assert all(r.category == "prompt" for r in PROMPT_RULES)
