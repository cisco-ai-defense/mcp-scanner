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
"""Built-in lint rules for MCP server-level validation (5 rules)."""

from __future__ import annotations

from typing import Any, Dict, List

from ..finding import LintFinding, LintSeverity
from ..rule import LintRule

_MAX_TOOLS = 100


class ServerHasCapabilities(LintRule):
    def __init__(self) -> None:
        super().__init__("server-has-capabilities", LintSeverity.WARNING, "server", "Server should expose tools, prompts, or resources")

    def check(self, item: Dict[str, Any], context: Dict[str, Any]) -> List[LintFinding]:
        tools = item.get("tools", [])
        prompts = item.get("prompts", [])
        resources = item.get("resources", [])
        if not tools and not prompts and not resources:
            return [self._finding(
                "Server does not expose any tools, prompts, or resources",
                "Register at least one tool, prompt, or resource",
            )]
        return []


class ServerToolNamesUnique(LintRule):
    def __init__(self) -> None:
        super().__init__("server-tool-names-unique", LintSeverity.ERROR, "server", "All tool names must be unique")

    def check(self, item: Dict[str, Any], context: Dict[str, Any]) -> List[LintFinding]:
        tools = item.get("tools", [])
        names: Dict[str, int] = {}
        for t in tools:
            n = t.get("name", "")
            names[n] = names.get(n, 0) + 1
        dupes = [n for n, c in names.items() if c > 1 and n]
        if dupes:
            return [self._finding(
                f"Duplicate tool names: {', '.join(dupes)}",
                "Ensure every tool has a unique name",
                affected_items=len(dupes),
            )]
        return []


class ServerPromptNamesUnique(LintRule):
    def __init__(self) -> None:
        super().__init__("server-prompt-names-unique", LintSeverity.ERROR, "server", "All prompt names must be unique")

    def check(self, item: Dict[str, Any], context: Dict[str, Any]) -> List[LintFinding]:
        prompts = item.get("prompts", [])
        names: Dict[str, int] = {}
        for p in prompts:
            n = p.get("name", "")
            names[n] = names.get(n, 0) + 1
        dupes = [n for n, c in names.items() if c > 1 and n]
        if dupes:
            return [self._finding(
                f"Duplicate prompt names: {', '.join(dupes)}",
                "Ensure every prompt has a unique name",
                affected_items=len(dupes),
            )]
        return []


class ServerResourceUrisUnique(LintRule):
    def __init__(self) -> None:
        super().__init__("server-resource-uris-unique", LintSeverity.ERROR, "server", "All resource URIs must be unique")

    def check(self, item: Dict[str, Any], context: Dict[str, Any]) -> List[LintFinding]:
        resources = item.get("resources", [])
        uris: Dict[str, int] = {}
        for r in resources:
            u = r.get("uri", "")
            uris[u] = uris.get(u, 0) + 1
        dupes = [u for u, c in uris.items() if c > 1 and u]
        if dupes:
            return [self._finding(
                f"Duplicate resource URIs: {', '.join(dupes)}",
                "Ensure every resource has a unique URI",
                affected_items=len(dupes),
            )]
        return []


class ServerNoExcessiveTools(LintRule):
    def __init__(self) -> None:
        super().__init__("server-no-excessive-tools", LintSeverity.INFO, "server", f"Server should not expose more than {_MAX_TOOLS} tools")

    def check(self, item: Dict[str, Any], context: Dict[str, Any]) -> List[LintFinding]:
        tools = item.get("tools", [])
        if len(tools) > _MAX_TOOLS:
            return [self._finding(
                f"Server exposes {len(tools)} tools (recommended max {_MAX_TOOLS})",
                "Consider splitting into multiple focused servers or using tool namespacing",
                affected_items=len(tools),
            )]
        return []


SERVER_RULES: List[LintRule] = [
    ServerHasCapabilities(),
    ServerPromptNamesUnique(),
    ServerResourceUrisUnique(),
    ServerToolNamesUnique(),
    ServerNoExcessiveTools(),
]
