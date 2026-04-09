# Copyright 2026 Cisco Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the 18 built-in tool lint rules."""

import pytest

from mcpscanner.core.analyzers.linter.rules.tool_rules import TOOL_RULES

CTX = {}


def _find_rule(rule_id):
    for r in TOOL_RULES:
        if r.id == rule_id:
            return r
    raise ValueError(f"Rule {rule_id} not found")


# ---- tool-has-name ----

class TestToolHasName:
    RULE = _find_rule("tool-has-name")

    def test_pass_with_name(self):
        assert self.RULE.check({"name": "my_tool"}, CTX) == []

    def test_fail_empty_name(self):
        findings = self.RULE.check({"name": ""}, CTX)
        assert len(findings) == 1
        assert findings[0].severity.value == "error"

    def test_fail_missing_name(self):
        findings = self.RULE.check({}, CTX)
        assert len(findings) == 1

    def test_fail_whitespace_name(self):
        findings = self.RULE.check({"name": "   "}, CTX)
        assert len(findings) == 1


# ---- tool-has-description ----

class TestToolHasDescription:
    RULE = _find_rule("tool-has-description")

    def test_pass(self):
        assert self.RULE.check({"name": "t", "description": "Does something"}, CTX) == []

    def test_fail_missing(self):
        findings = self.RULE.check({"name": "t"}, CTX)
        assert len(findings) == 1
        assert findings[0].severity.value == "warning"

    def test_fail_empty(self):
        findings = self.RULE.check({"name": "t", "description": ""}, CTX)
        assert len(findings) == 1


# ---- tool-description-min-length ----

class TestToolDescriptionMinLength:
    RULE = _find_rule("tool-description-min-length")

    def test_pass_long_enough(self):
        assert self.RULE.check({"name": "t", "description": "A" * 20}, CTX) == []

    def test_pass_no_description(self):
        assert self.RULE.check({"name": "t"}, CTX) == []

    def test_fail_too_short(self):
        findings = self.RULE.check({"name": "t", "description": "Short"}, CTX)
        assert len(findings) == 1
        assert findings[0].severity.value == "info"


# ---- tool-description-not-name ----

class TestToolDescriptionNotName:
    RULE = _find_rule("tool-description-not-name")

    def test_pass_different(self):
        assert self.RULE.check({"name": "get_user", "description": "Fetches a user by ID"}, CTX) == []

    def test_fail_same(self):
        findings = self.RULE.check({"name": "get_user", "description": "get_user"}, CTX)
        assert len(findings) == 1

    def test_fail_case_insensitive(self):
        findings = self.RULE.check({"name": "get_user", "description": "Get User"}, CTX)
        assert len(findings) == 1

    def test_pass_empty_desc(self):
        assert self.RULE.check({"name": "t", "description": ""}, CTX) == []


# ---- tool-name-convention ----

class TestToolNameConvention:
    RULE = _find_rule("tool-name-convention")

    def test_pass_snake_case(self):
        assert self.RULE.check({"name": "get_user_data"}, CTX) == []

    def test_pass_camel_case(self):
        assert self.RULE.check({"name": "getUserData"}, CTX) == []

    def test_fail_spaces(self):
        findings = self.RULE.check({"name": "Get User Data"}, CTX)
        assert len(findings) == 1

    def test_fail_pascal_case(self):
        findings = self.RULE.check({"name": "GetUserData"}, CTX)
        assert len(findings) == 1

    def test_pass_empty(self):
        assert self.RULE.check({"name": ""}, CTX) == []


# ---- tool-name-max-length ----

class TestToolNameMaxLength:
    RULE = _find_rule("tool-name-max-length")

    def test_pass_normal_length(self):
        assert self.RULE.check({"name": "my_tool"}, CTX) == []

    def test_fail_too_long(self):
        findings = self.RULE.check({"name": "a" * 65}, CTX)
        assert len(findings) == 1

    def test_pass_exact_limit(self):
        assert self.RULE.check({"name": "a" * 64}, CTX) == []


# ---- tool-has-input-schema ----

class TestToolHasInputSchema:
    RULE = _find_rule("tool-has-input-schema")

    def test_pass(self):
        assert self.RULE.check({"name": "t", "inputSchema": {"type": "object"}}, CTX) == []

    def test_fail(self):
        findings = self.RULE.check({"name": "t"}, CTX)
        assert len(findings) == 1


# ---- tool-input-schema-has-properties ----

class TestToolInputSchemaHasProperties:
    RULE = _find_rule("tool-input-schema-has-properties")

    def test_pass_with_properties(self):
        tool = {"name": "t", "inputSchema": {"type": "object", "properties": {"a": {"type": "string"}}}}
        assert self.RULE.check(tool, CTX) == []

    def test_fail_no_properties(self):
        tool = {"name": "t", "inputSchema": {"type": "object"}}
        findings = self.RULE.check(tool, CTX)
        assert len(findings) == 1

    def test_pass_no_schema(self):
        assert self.RULE.check({"name": "t"}, CTX) == []


# ---- tool-input-schema-has-required ----

class TestToolInputSchemaHasRequired:
    RULE = _find_rule("tool-input-schema-has-required")

    def test_pass_with_required(self):
        tool = {"name": "t", "inputSchema": {"properties": {"a": {}}, "required": ["a"]}}
        assert self.RULE.check(tool, CTX) == []

    def test_fail_no_required(self):
        tool = {"name": "t", "inputSchema": {"properties": {"a": {}}}}
        findings = self.RULE.check(tool, CTX)
        assert len(findings) == 1

    def test_pass_no_properties(self):
        tool = {"name": "t", "inputSchema": {}}
        assert self.RULE.check(tool, CTX) == []


# ---- tool-required-params-defined ----

class TestToolRequiredParamsDefined:
    RULE = _find_rule("tool-required-params-defined")

    def test_pass_all_defined(self):
        tool = {"name": "t", "inputSchema": {"properties": {"a": {}}, "required": ["a"]}}
        assert self.RULE.check(tool, CTX) == []

    def test_fail_undefined_param(self):
        tool = {"name": "t", "inputSchema": {"properties": {"a": {}}, "required": ["a", "b"]}}
        findings = self.RULE.check(tool, CTX)
        assert len(findings) == 1
        assert "b" in findings[0].message

    def test_pass_no_required(self):
        tool = {"name": "t", "inputSchema": {"properties": {"a": {}}}}
        assert self.RULE.check(tool, CTX) == []


# ---- tool-schema-properties-have-types ----

class TestToolSchemaPropertiesHaveTypes:
    RULE = _find_rule("tool-schema-properties-have-types")

    def test_pass_all_typed(self):
        tool = {"name": "t", "inputSchema": {"properties": {"a": {"type": "string"}}}}
        assert self.RULE.check(tool, CTX) == []

    def test_fail_untyped(self):
        tool = {"name": "t", "inputSchema": {"properties": {"a": {"description": "no type"}}}}
        findings = self.RULE.check(tool, CTX)
        assert len(findings) == 1
        assert "a" in findings[0].message

    def test_pass_empty_properties(self):
        tool = {"name": "t", "inputSchema": {"properties": {}}}
        assert self.RULE.check(tool, CTX) == []


# ---- tool-schema-properties-have-descriptions ----

class TestToolSchemaPropertiesHaveDescriptions:
    RULE = _find_rule("tool-schema-properties-have-descriptions")

    def test_pass_all_described(self):
        tool = {"name": "t", "inputSchema": {"properties": {"a": {"description": "desc"}}}}
        assert self.RULE.check(tool, CTX) == []

    def test_fail_undescribed(self):
        tool = {"name": "t", "inputSchema": {"properties": {"a": {"type": "string"}}}}
        findings = self.RULE.check(tool, CTX)
        assert len(findings) == 1

    def test_multiple_undescribed(self):
        tool = {"name": "t", "inputSchema": {"properties": {"a": {}, "b": {}}}}
        findings = self.RULE.check(tool, CTX)
        assert len(findings) == 1
        assert findings[0].affected_items == 2


# ---- tool-schema-has-examples ----

class TestToolSchemaHasExamples:
    RULE = _find_rule("tool-schema-has-examples")

    def test_pass_with_example(self):
        tool = {"name": "t", "inputSchema": {"properties": {"a": {"example": "foo"}}}}
        assert self.RULE.check(tool, CTX) == []

    def test_pass_with_default(self):
        tool = {"name": "t", "inputSchema": {"properties": {"a": {"default": "bar"}}}}
        assert self.RULE.check(tool, CTX) == []

    def test_pass_with_examples(self):
        tool = {"name": "t", "inputSchema": {"properties": {"a": {"examples": ["x"]}}}}
        assert self.RULE.check(tool, CTX) == []

    def test_fail_no_example(self):
        tool = {"name": "t", "inputSchema": {"properties": {"a": {"type": "string"}}}}
        findings = self.RULE.check(tool, CTX)
        assert len(findings) == 1


# ---- tool-output-schema-defined ----

class TestToolOutputSchemaDefined:
    RULE = _find_rule("tool-output-schema-defined")

    def test_pass(self):
        assert self.RULE.check({"name": "t", "outputSchema": {}}, CTX) == []

    def test_fail(self):
        findings = self.RULE.check({"name": "t"}, CTX)
        assert len(findings) == 1


# ---- tool-no-empty-enum ----

class TestToolNoEmptyEnum:
    RULE = _find_rule("tool-no-empty-enum")

    def test_pass_no_enum(self):
        tool = {"name": "t", "inputSchema": {"properties": {"a": {"type": "string"}}}}
        assert self.RULE.check(tool, CTX) == []

    def test_pass_populated_enum(self):
        tool = {"name": "t", "inputSchema": {"properties": {"a": {"type": "string", "enum": ["x", "y"]}}}}
        assert self.RULE.check(tool, CTX) == []

    def test_fail_empty_enum(self):
        tool = {"name": "t", "inputSchema": {"properties": {"a": {"type": "string", "enum": []}}}}
        findings = self.RULE.check(tool, CTX)
        assert len(findings) == 1


# ---- tool-schema-max-depth ----

class TestToolSchemaMaxDepth:
    RULE = _find_rule("tool-schema-max-depth")

    def test_pass_shallow(self):
        tool = {"name": "t", "inputSchema": {"properties": {"a": {"type": "string"}}}}
        assert self.RULE.check(tool, CTX) == []

    def test_fail_deep(self):
        nested = {"type": "object", "properties": {
            "l1": {"type": "object", "properties": {
                "l2": {"type": "object", "properties": {
                    "l3": {"type": "object", "properties": {
                        "l4": {"type": "object", "properties": {
                            "l5": {"type": "object", "properties": {
                                "l6": {"type": "string"}
                            }}
                        }}
                    }}
                }}
            }}
        }}
        tool = {"name": "t", "inputSchema": nested}
        findings = self.RULE.check(tool, CTX)
        assert len(findings) == 1


# ---- tool-no-duplicate-params ----

class TestToolNoDuplicateParams:
    RULE = _find_rule("tool-no-duplicate-params")

    def test_pass_unique(self):
        tool = {"name": "t", "inputSchema": {"properties": {"a": {}, "b": {}}}}
        assert self.RULE.check(tool, CTX) == []

    def test_fail_case_insensitive_dup(self):
        tool = {"name": "t", "inputSchema": {"properties": {"Param": {}, "param": {}}}}
        findings = self.RULE.check(tool, CTX)
        assert len(findings) == 1


# ---- tool-description-no-html ----

class TestToolDescriptionNoHtml:
    RULE = _find_rule("tool-description-no-html")

    def test_pass_plain(self):
        assert self.RULE.check({"name": "t", "description": "Simple text"}, CTX) == []

    def test_fail_html(self):
        findings = self.RULE.check({"name": "t", "description": "<p>HTML</p>"}, CTX)
        assert len(findings) == 1

    def test_fail_bold(self):
        findings = self.RULE.check({"name": "t", "description": "Some <b>bold</b>"}, CTX)
        assert len(findings) == 1

    def test_pass_angle_brackets_in_code(self):
        assert self.RULE.check({"name": "t", "description": "Returns x < 5 and y > 3"}, CTX) == []


# ---- Aggregate checks ----

class TestToolRulesCount:
    def test_total_rules(self):
        assert len(TOOL_RULES) == 18

    def test_unique_ids(self):
        ids = [r.id for r in TOOL_RULES]
        assert len(ids) == len(set(ids))

    def test_all_tool_category(self):
        assert all(r.category == "tool" for r in TOOL_RULES)
