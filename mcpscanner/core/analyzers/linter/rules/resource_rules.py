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
"""Built-in lint rules for MCP resource schemas (6 rules)."""

from __future__ import annotations

import re
from typing import Any, Dict, List
from urllib.parse import urlparse

from ..finding import LintFinding, LintSeverity
from ..rule import LintRule

_SNAKE_CASE = re.compile(r"^[a-z][a-z0-9]*(_[a-z0-9]+)*$")
_CAMEL_CASE = re.compile(r"^[a-z][a-zA-Z0-9]*$")
_KEBAB_CASE = re.compile(r"^[a-z][a-z0-9]*(-[a-z0-9]+)*$")
_MIME_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9!#$&\-^_.+]*\/[a-zA-Z0-9][a-zA-Z0-9!#$&\-^_.+]*$")


class ResourceHasName(LintRule):
    def __init__(self) -> None:
        super().__init__("resource-has-name", LintSeverity.ERROR, "resource", "Resource must have a non-empty name")

    def check(self, item: Dict[str, Any], context: Dict[str, Any]) -> List[LintFinding]:
        name = (item.get("name") or "").strip()
        if not name:
            uri = item.get("uri", "")
            return [self._finding(
                f"Resource '{uri}' is missing a name",
                "Add a 'name' field to the resource definition",
                item_name=uri,
            )]
        return []


class ResourceHasDescription(LintRule):
    def __init__(self) -> None:
        super().__init__("resource-has-description", LintSeverity.WARNING, "resource", "Resource should have a description")

    def check(self, item: Dict[str, Any], context: Dict[str, Any]) -> List[LintFinding]:
        name = item.get("name", item.get("uri", ""))
        desc = (item.get("description") or "").strip()
        if not desc:
            return [self._finding(
                f"Resource '{name}' has no description",
                "Add a 'description' that explains what this resource provides",
                item_name=name,
            )]
        return []


class ResourceHasMimeType(LintRule):
    def __init__(self) -> None:
        super().__init__("resource-has-mime-type", LintSeverity.WARNING, "resource", "Resource should specify a MIME type")

    def check(self, item: Dict[str, Any], context: Dict[str, Any]) -> List[LintFinding]:
        name = item.get("name", item.get("uri", ""))
        if not item.get("mimeType"):
            return [self._finding(
                f"Resource '{name}' has no MIME type specified",
                "Add a 'mimeType' field (e.g. 'application/json', 'text/plain')",
                item_name=name,
            )]
        return []


class ResourceMimeTypeValid(LintRule):
    def __init__(self) -> None:
        super().__init__("resource-mime-type-valid", LintSeverity.WARNING, "resource", "MIME type should be valid format")

    def check(self, item: Dict[str, Any], context: Dict[str, Any]) -> List[LintFinding]:
        name = item.get("name", item.get("uri", ""))
        mime = item.get("mimeType", "")
        if mime and not _MIME_PATTERN.match(mime):
            return [self._finding(
                f"Resource '{name}' has invalid MIME type '{mime}'",
                "Use a valid MIME type format (e.g. 'application/json')",
                item_name=name,
            )]
        return []


class ResourceUriValid(LintRule):
    def __init__(self) -> None:
        super().__init__("resource-uri-valid", LintSeverity.INFO, "resource", "URI should be well-formed")

    def check(self, item: Dict[str, Any], context: Dict[str, Any]) -> List[LintFinding]:
        name = item.get("name", "")
        uri = (item.get("uri") or "").strip()
        if not uri:
            return [self._finding(
                f"Resource '{name}' has no URI",
                "Add a 'uri' field to identify this resource",
                item_name=name,
            )]
        parsed = urlparse(uri)
        if not parsed.scheme:
            return [self._finding(
                f"Resource '{name}' URI '{uri}' has no scheme",
                "Use a fully-qualified URI with a scheme (e.g. 'file://', 'https://')",
                item_name=name,
            )]
        return []


class ResourceNameConvention(LintRule):
    def __init__(self) -> None:
        super().__init__("resource-name-convention", LintSeverity.INFO, "resource", "Name should follow a consistent convention")

    def check(self, item: Dict[str, Any], context: Dict[str, Any]) -> List[LintFinding]:
        name = (item.get("name") or "").strip()
        if not name:
            return []
        # Resources have broader naming: allow snake, camel, kebab, or phrases with spaces
        if _SNAKE_CASE.match(name) or _CAMEL_CASE.match(name) or _KEBAB_CASE.match(name):
            return []
        if " " in name and name == name.strip() and "  " not in name:
            return []
        return [self._finding(
            f"Resource name '{name}' uses inconsistent naming",
            "Use a consistent convention: snake_case, camelCase, kebab-case, or readable phrases",
            item_name=name,
        )]


RESOURCE_RULES: List[LintRule] = [
    ResourceHasName(),
    ResourceHasDescription(),
    ResourceHasMimeType(),
    ResourceMimeTypeValid(),
    ResourceUriValid(),
    ResourceNameConvention(),
]
