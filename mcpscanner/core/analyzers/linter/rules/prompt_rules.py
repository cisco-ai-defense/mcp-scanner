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
"""Built-in lint rules for MCP prompt schemas (8 rules)."""

from __future__ import annotations

import re
from typing import Any, Dict, List

from ..finding import LintFinding, LintSeverity
from ..rule import LintRule

_SNAKE_CASE = re.compile(r"^[a-z][a-z0-9]*(_[a-z0-9]+)*$")
_CAMEL_CASE = re.compile(r"^[a-z][a-zA-Z0-9]*$")
_KEBAB_CASE = re.compile(r"^[a-z][a-z0-9]*(-[a-z0-9]+)*$")
_MIN_DESC_LEN = 20


class PromptHasName(LintRule):
    def __init__(self) -> None:
        super().__init__("prompt-has-name", LintSeverity.ERROR, "prompt", "Prompt must have a non-empty name")

    def check(self, item: Dict[str, Any], context: Dict[str, Any]) -> List[LintFinding]:
        name = (item.get("name") or "").strip()
        if not name:
            return [self._finding("Prompt is missing a name", "Add a 'name' field to the prompt definition")]
        return []


class PromptHasDescription(LintRule):
    def __init__(self) -> None:
        super().__init__("prompt-has-description", LintSeverity.WARNING, "prompt", "Prompt must have a description")

    def check(self, item: Dict[str, Any], context: Dict[str, Any]) -> List[LintFinding]:
        name = item.get("name", "")
        desc = (item.get("description") or "").strip()
        if not desc:
            return [self._finding(
                f"Prompt '{name}' has no description",
                "Add a 'description' that explains what this prompt does",
                item_name=name,
            )]
        return []


class PromptDescriptionMinLength(LintRule):
    def __init__(self) -> None:
        super().__init__("prompt-description-min-length", LintSeverity.INFO, "prompt", f"Description should be at least {_MIN_DESC_LEN} characters")

    def check(self, item: Dict[str, Any], context: Dict[str, Any]) -> List[LintFinding]:
        name = item.get("name", "")
        desc = (item.get("description") or "").strip()
        if desc and len(desc) < _MIN_DESC_LEN:
            return [self._finding(
                f"Prompt '{name}' description is only {len(desc)} characters",
                f"Expand the description to at least {_MIN_DESC_LEN} characters",
                item_name=name,
            )]
        return []


class PromptNameConvention(LintRule):
    def __init__(self) -> None:
        super().__init__("prompt-name-convention", LintSeverity.INFO, "prompt", "Name should follow a consistent convention")

    def check(self, item: Dict[str, Any], context: Dict[str, Any]) -> List[LintFinding]:
        name = (item.get("name") or "").strip()
        if not name:
            return []
        if _SNAKE_CASE.match(name) or _CAMEL_CASE.match(name) or _KEBAB_CASE.match(name):
            return []
        return [self._finding(
            f"Prompt name '{name}' does not follow a standard convention",
            "Use snake_case, camelCase, or kebab-case for prompt names",
            item_name=name,
        )]


class PromptHasArguments(LintRule):
    def __init__(self) -> None:
        super().__init__("prompt-has-arguments", LintSeverity.INFO, "prompt", "Prompt should define arguments")

    def check(self, item: Dict[str, Any], context: Dict[str, Any]) -> List[LintFinding]:
        name = item.get("name", "")
        args = item.get("arguments")
        if args is None:
            return [self._finding(
                f"Prompt '{name}' does not define any arguments",
                "Add an 'arguments' list to describe expected inputs (even if empty)",
                item_name=name,
            )]
        return []


class PromptArgumentHasDescription(LintRule):
    def __init__(self) -> None:
        super().__init__("prompt-argument-has-description", LintSeverity.INFO, "prompt", "Each argument should have a description")

    def check(self, item: Dict[str, Any], context: Dict[str, Any]) -> List[LintFinding]:
        name = item.get("name", "")
        args = item.get("arguments", [])
        if not isinstance(args, list):
            return []
        undescribed = [a.get("name", "?") for a in args if isinstance(a, dict) and not a.get("description")]
        if undescribed:
            return [self._finding(
                f"Prompt '{name}' arguments missing descriptions: {', '.join(undescribed)}",
                "Add a 'description' to each argument",
                item_name=name,
                affected_items=len(undescribed),
            )]
        return []


class PromptArgumentHasRequired(LintRule):
    def __init__(self) -> None:
        super().__init__("prompt-argument-has-required", LintSeverity.INFO, "prompt", "Arguments should specify required flag")

    def check(self, item: Dict[str, Any], context: Dict[str, Any]) -> List[LintFinding]:
        name = item.get("name", "")
        args = item.get("arguments", [])
        if not isinstance(args, list):
            return []
        missing_req = [a.get("name", "?") for a in args if isinstance(a, dict) and "required" not in a]
        if missing_req:
            return [self._finding(
                f"Prompt '{name}' arguments missing 'required' flag: {', '.join(missing_req)}",
                "Set 'required: true' or 'required: false' on each argument",
                item_name=name,
                affected_items=len(missing_req),
            )]
        return []


class PromptNoDuplicateArguments(LintRule):
    def __init__(self) -> None:
        super().__init__("prompt-no-duplicate-arguments", LintSeverity.ERROR, "prompt", "No duplicate argument names")

    def check(self, item: Dict[str, Any], context: Dict[str, Any]) -> List[LintFinding]:
        name = item.get("name", "")
        args = item.get("arguments", [])
        if not isinstance(args, list):
            return []
        seen: set[str] = set()
        dupes: List[str] = []
        for a in args:
            if isinstance(a, dict):
                arg_name = a.get("name", "")
                if arg_name in seen:
                    dupes.append(arg_name)
                seen.add(arg_name)
        if dupes:
            return [self._finding(
                f"Prompt '{name}' has duplicate argument names: {', '.join(dupes)}",
                "Use unique names for each argument",
                item_name=name,
                affected_items=len(dupes),
            )]
        return []


PROMPT_RULES: List[LintRule] = [
    PromptHasName(),
    PromptHasDescription(),
    PromptDescriptionMinLength(),
    PromptNameConvention(),
    PromptHasArguments(),
    PromptArgumentHasDescription(),
    PromptArgumentHasRequired(),
    PromptNoDuplicateArguments(),
]
