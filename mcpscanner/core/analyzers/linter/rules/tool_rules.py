# Copyright 2026 Cisco Systems, Inc.
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
"""Built-in lint rules for MCP tool schemas (18 rules)."""

from __future__ import annotations

import re
from typing import Any, Dict, List

from ..finding import LintFinding, LintSeverity
from ..rule import LintRule

_SNAKE_CASE = re.compile(r"^[a-z][a-z0-9]*(_[a-z0-9]+)*$")
_CAMEL_CASE = re.compile(r"^[a-z][a-zA-Z0-9]*$")
_HTML_TAG = re.compile(r"<\s*/?\s*[a-zA-Z][^>]*>")
_MAX_NAME_LEN = 64
_MIN_DESC_LEN = 20
_MAX_SCHEMA_DEPTH = 5


class ToolHasName(LintRule):
    def __init__(self) -> None:
        super().__init__("tool-has-name", LintSeverity.ERROR, "tool", "Tool must have a non-empty name")

    def check(self, item: Dict[str, Any], context: Dict[str, Any]) -> List[LintFinding]:
        name = (item.get("name") or "").strip()
        if not name:
            return [self._finding("Tool is missing a name", "Add a 'name' field to the tool definition")]
        return []


class ToolHasDescription(LintRule):
    def __init__(self) -> None:
        super().__init__("tool-has-description", LintSeverity.WARNING, "tool", "Tool must have a description")

    def check(self, item: Dict[str, Any], context: Dict[str, Any]) -> List[LintFinding]:
        name = item.get("name", "")
        desc = (item.get("description") or "").strip()
        if not desc:
            return [self._finding(f"Tool '{name}' has no description", "Add a 'description' that explains what this tool does", item_name=name)]
        return []


class ToolDescriptionMinLength(LintRule):
    def __init__(self) -> None:
        super().__init__("tool-description-min-length", LintSeverity.INFO, "tool", f"Description should be at least {_MIN_DESC_LEN} characters")

    def check(self, item: Dict[str, Any], context: Dict[str, Any]) -> List[LintFinding]:
        name = item.get("name", "")
        desc = (item.get("description") or "").strip()
        if desc and len(desc) < _MIN_DESC_LEN:
            return [self._finding(
                f"Tool '{name}' description is only {len(desc)} characters",
                f"Expand the description to at least {_MIN_DESC_LEN} characters for clarity",
                item_name=name,
            )]
        return []


class ToolDescriptionNotName(LintRule):
    def __init__(self) -> None:
        super().__init__("tool-description-not-name", LintSeverity.WARNING, "tool", "Description should not just repeat the name")

    def check(self, item: Dict[str, Any], context: Dict[str, Any]) -> List[LintFinding]:
        name = (item.get("name") or "").strip()
        desc = (item.get("description") or "").strip()
        if name and desc and desc.lower().replace("_", " ") == name.lower().replace("_", " "):
            return [self._finding(
                f"Tool '{name}' description just repeats the tool name",
                "Write a meaningful description that explains the tool's purpose",
                item_name=name,
            )]
        return []


class ToolNameConvention(LintRule):
    def __init__(self) -> None:
        super().__init__("tool-name-convention", LintSeverity.INFO, "tool", "Name should follow snake_case or camelCase")

    def check(self, item: Dict[str, Any], context: Dict[str, Any]) -> List[LintFinding]:
        name = (item.get("name") or "").strip()
        if not name:
            return []
        if _SNAKE_CASE.match(name) or _CAMEL_CASE.match(name):
            return []
        return [self._finding(
            f"Tool name '{name}' does not follow snake_case or camelCase",
            "Rename to snake_case (e.g. 'my_tool') or camelCase (e.g. 'myTool')",
            item_name=name,
        )]


class ToolNameMaxLength(LintRule):
    def __init__(self) -> None:
        super().__init__("tool-name-max-length", LintSeverity.INFO, "tool", f"Name should be under {_MAX_NAME_LEN} characters")

    def check(self, item: Dict[str, Any], context: Dict[str, Any]) -> List[LintFinding]:
        name = (item.get("name") or "").strip()
        if name and len(name) > _MAX_NAME_LEN:
            return [self._finding(
                f"Tool name '{name}' is {len(name)} characters (max {_MAX_NAME_LEN})",
                f"Shorten the tool name to under {_MAX_NAME_LEN} characters",
                item_name=name,
            )]
        return []


class ToolHasInputSchema(LintRule):
    def __init__(self) -> None:
        super().__init__("tool-has-input-schema", LintSeverity.WARNING, "tool", "Tool should define an inputSchema")

    def check(self, item: Dict[str, Any], context: Dict[str, Any]) -> List[LintFinding]:
        name = item.get("name", "")
        if "inputSchema" not in item:
            return [self._finding(
                f"Tool '{name}' has no inputSchema defined",
                "Add an 'inputSchema' to define the expected parameters",
                item_name=name,
            )]
        return []


class ToolInputSchemaHasProperties(LintRule):
    def __init__(self) -> None:
        super().__init__("tool-input-schema-has-properties", LintSeverity.WARNING, "tool", "inputSchema should define properties")

    def check(self, item: Dict[str, Any], context: Dict[str, Any]) -> List[LintFinding]:
        name = item.get("name", "")
        schema = item.get("inputSchema", {})
        if not isinstance(schema, dict):
            return []
        if schema and "properties" not in schema:
            return [self._finding(
                f"Tool '{name}' inputSchema has no 'properties' defined",
                "Add a 'properties' object to describe each parameter",
                item_name=name,
                location="inputSchema",
            )]
        return []


class ToolInputSchemaHasRequired(LintRule):
    def __init__(self) -> None:
        super().__init__("tool-input-schema-has-required", LintSeverity.INFO, "tool", "inputSchema should declare required fields")

    def check(self, item: Dict[str, Any], context: Dict[str, Any]) -> List[LintFinding]:
        name = item.get("name", "")
        schema = item.get("inputSchema", {})
        if not isinstance(schema, dict):
            return []
        props = schema.get("properties", {})
        if props and "required" not in schema:
            return [self._finding(
                f"Tool '{name}' inputSchema has properties but no 'required' list",
                "Add a 'required' array listing mandatory parameters",
                item_name=name,
                location="inputSchema",
            )]
        return []


class ToolRequiredParamsDefined(LintRule):
    def __init__(self) -> None:
        super().__init__("tool-required-params-defined", LintSeverity.ERROR, "tool", "Required params must exist in properties")

    def check(self, item: Dict[str, Any], context: Dict[str, Any]) -> List[LintFinding]:
        name = item.get("name", "")
        schema = item.get("inputSchema", {})
        if not isinstance(schema, dict):
            return []
        props = schema.get("properties", {})
        required = schema.get("required", [])
        if not isinstance(required, list) or not isinstance(props, dict):
            return []
        missing = [r for r in required if r not in props]
        if missing:
            return [self._finding(
                f"Tool '{name}' requires undefined parameters: {', '.join(missing)}",
                "Either add the missing properties or remove them from 'required'",
                item_name=name,
                location="inputSchema.required",
                affected_items=len(missing),
            )]
        return []


class ToolSchemaPropertiesHaveTypes(LintRule):
    def __init__(self) -> None:
        super().__init__("tool-schema-properties-have-types", LintSeverity.WARNING, "tool", "Each property should have a type")

    def check(self, item: Dict[str, Any], context: Dict[str, Any]) -> List[LintFinding]:
        name = item.get("name", "")
        schema = item.get("inputSchema", {})
        if not isinstance(schema, dict):
            return []
        props = schema.get("properties", {})
        if not isinstance(props, dict):
            return []
        untyped = [k for k, v in props.items() if isinstance(v, dict) and "type" not in v]
        if untyped:
            return [self._finding(
                f"Tool '{name}' properties missing 'type': {', '.join(untyped)}",
                "Add a 'type' field (e.g. 'string', 'integer') to each property",
                item_name=name,
                location="inputSchema.properties",
                affected_items=len(untyped),
            )]
        return []


class ToolSchemaPropertiesHaveDescriptions(LintRule):
    def __init__(self) -> None:
        super().__init__("tool-schema-properties-have-descriptions", LintSeverity.INFO, "tool", "Each property should have a description")

    def check(self, item: Dict[str, Any], context: Dict[str, Any]) -> List[LintFinding]:
        name = item.get("name", "")
        schema = item.get("inputSchema", {})
        if not isinstance(schema, dict):
            return []
        props = schema.get("properties", {})
        if not isinstance(props, dict):
            return []
        undescribed = [k for k, v in props.items() if isinstance(v, dict) and not v.get("description")]
        if undescribed:
            return [self._finding(
                f"Tool '{name}' properties missing descriptions: {', '.join(undescribed)}",
                "Add a 'description' to each property for better documentation",
                item_name=name,
                location="inputSchema.properties",
                affected_items=len(undescribed),
            )]
        return []


class ToolSchemaHasExamples(LintRule):
    def __init__(self) -> None:
        super().__init__("tool-schema-has-examples", LintSeverity.INFO, "tool", "Properties should include examples")

    def check(self, item: Dict[str, Any], context: Dict[str, Any]) -> List[LintFinding]:
        name = item.get("name", "")
        schema = item.get("inputSchema", {})
        if not isinstance(schema, dict):
            return []
        props = schema.get("properties", {})
        if not isinstance(props, dict):
            return []
        no_example = [
            k for k, v in props.items()
            if isinstance(v, dict) and "example" not in v and "examples" not in v and "default" not in v
        ]
        if no_example:
            return [self._finding(
                f"Tool '{name}' properties missing examples: {', '.join(no_example)}",
                "Add 'example' field to properties for better documentation",
                item_name=name,
                location="inputSchema.properties",
                affected_items=len(no_example),
            )]
        return []


class ToolOutputSchemaDefined(LintRule):
    def __init__(self) -> None:
        super().__init__("tool-output-schema-defined", LintSeverity.INFO, "tool", "Tool should define an outputSchema")

    def check(self, item: Dict[str, Any], context: Dict[str, Any]) -> List[LintFinding]:
        name = item.get("name", "")
        if "outputSchema" not in item:
            return [self._finding(
                f"Tool '{name}' has no outputSchema defined",
                "Add an outputSchema to define the structure of tool results",
                item_name=name,
            )]
        return []


class ToolNoEmptyEnum(LintRule):
    def __init__(self) -> None:
        super().__init__("tool-no-empty-enum", LintSeverity.WARNING, "tool", "Enum properties must have values")

    def check(self, item: Dict[str, Any], context: Dict[str, Any]) -> List[LintFinding]:
        name = item.get("name", "")
        schema = item.get("inputSchema", {})
        if not isinstance(schema, dict):
            return []
        props = schema.get("properties", {})
        if not isinstance(props, dict):
            return []
        empty_enums = [k for k, v in props.items() if isinstance(v, dict) and "enum" in v and not v["enum"]]
        if empty_enums:
            return [self._finding(
                f"Tool '{name}' has empty enum for: {', '.join(empty_enums)}",
                "Provide at least one value in the 'enum' array",
                item_name=name,
                location="inputSchema.properties",
                affected_items=len(empty_enums),
            )]
        return []


def _schema_depth(schema: Any, current: int = 0) -> int:
    if not isinstance(schema, dict):
        return current
    deepest = current
    for key in ("properties", "items", "additionalProperties"):
        child = schema.get(key)
        if isinstance(child, dict):
            if key == "properties":
                for v in child.values():
                    deepest = max(deepest, _schema_depth(v, current + 1))
            else:
                deepest = max(deepest, _schema_depth(child, current + 1))
    return deepest


class ToolSchemaMaxDepth(LintRule):
    def __init__(self) -> None:
        super().__init__("tool-schema-max-depth", LintSeverity.WARNING, "tool", f"Schema nesting should not exceed depth {_MAX_SCHEMA_DEPTH}")

    def check(self, item: Dict[str, Any], context: Dict[str, Any]) -> List[LintFinding]:
        name = item.get("name", "")
        schema = item.get("inputSchema", {})
        if not isinstance(schema, dict):
            return []
        depth = _schema_depth(schema)
        if depth > _MAX_SCHEMA_DEPTH:
            return [self._finding(
                f"Tool '{name}' inputSchema nesting depth is {depth} (max {_MAX_SCHEMA_DEPTH})",
                "Flatten the schema structure to reduce complexity",
                item_name=name,
                location="inputSchema",
            )]
        return []


class ToolNoDuplicateParams(LintRule):
    def __init__(self) -> None:
        super().__init__("tool-no-duplicate-params", LintSeverity.ERROR, "tool", "No duplicate property names in schema")

    def check(self, item: Dict[str, Any], context: Dict[str, Any]) -> List[LintFinding]:
        # JSON object keys are unique by spec; this checks for case-insensitive collisions
        name = item.get("name", "")
        schema = item.get("inputSchema", {})
        if not isinstance(schema, dict):
            return []
        props = schema.get("properties", {})
        if not isinstance(props, dict):
            return []
        seen: Dict[str, str] = {}
        dupes: List[str] = []
        for k in props:
            lower = k.lower()
            if lower in seen:
                dupes.append(f"'{k}' vs '{seen[lower]}'")
            else:
                seen[lower] = k
        if dupes:
            return [self._finding(
                f"Tool '{name}' has case-insensitive duplicate parameters: {', '.join(dupes)}",
                "Use distinct parameter names to avoid confusion",
                item_name=name,
                location="inputSchema.properties",
                affected_items=len(dupes),
            )]
        return []


class ToolDescriptionNoHtml(LintRule):
    def __init__(self) -> None:
        super().__init__("tool-description-no-html", LintSeverity.INFO, "tool", "Description should not contain HTML tags")

    def check(self, item: Dict[str, Any], context: Dict[str, Any]) -> List[LintFinding]:
        name = item.get("name", "")
        desc = item.get("description") or ""
        if _HTML_TAG.search(desc):
            return [self._finding(
                f"Tool '{name}' description contains HTML tags",
                "Use plain text in descriptions; HTML will not render in most MCP clients",
                item_name=name,
            )]
        return []


TOOL_RULES: List[LintRule] = [
    ToolHasName(),
    ToolHasDescription(),
    ToolDescriptionMinLength(),
    ToolDescriptionNotName(),
    ToolNameConvention(),
    ToolNameMaxLength(),
    ToolHasInputSchema(),
    ToolInputSchemaHasProperties(),
    ToolInputSchemaHasRequired(),
    ToolRequiredParamsDefined(),
    ToolSchemaPropertiesHaveTypes(),
    ToolSchemaPropertiesHaveDescriptions(),
    ToolSchemaHasExamples(),
    ToolOutputSchemaDefined(),
    ToolNoEmptyEnum(),
    ToolSchemaMaxDepth(),
    ToolNoDuplicateParams(),
    ToolDescriptionNoHtml(),
]
