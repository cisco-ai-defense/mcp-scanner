# Copyright 2025 Cisco Systems, Inc. and its affiliates
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

"""Classify tool schema references without dereferencing them."""

import ipaddress
import json
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

from .base import BaseAnalyzer, SecurityFinding


class SchemaReferenceAnalyzer(BaseAnalyzer):
    """Inspect advertised input/output schemas for indirect content sources."""

    MAX_NODES = 5000
    MAX_REFS = 32

    def __init__(self) -> None:
        super().__init__("SCHEMA")

    async def analyze(
        self, content: str, context: Optional[Dict[str, Any]] = None
    ) -> List[SecurityFinding]:
        if context and context.get("content_type") == "description":
            return []
        try:
            tool = json.loads(content)
        except (TypeError, ValueError):
            return []
        if not isinstance(tool, dict):
            return []

        findings: List[SecurityFinding] = []
        stack = [
            (schema, f"{key}", 0)
            for key in ("inputSchema", "outputSchema")
            if isinstance((schema := tool.get(key)), (dict, list))
        ]
        nodes = 0
        while stack and nodes < self.MAX_NODES and len(findings) < self.MAX_REFS:
            value, path, depth = stack.pop()
            nodes += 1
            if isinstance(value, dict):
                ref = value.get("$ref")
                if isinstance(ref, str):
                    classified = self._classify_ref(ref)
                    if classified is not None:
                        severity, category = classified
                        findings.append(
                            self.create_security_finding(
                                severity=severity,
                                summary=f"Tool schema contains a {category} $ref. "
                                "A client that resolves it may load additional content.",
                                threat_category="Indirect Schema Reference",
                                details={
                                    "check_id": "MCPS-011",
                                    "classification": category,
                                    "schema_path": f"{path}.$ref",
                                    "reference": ref[:500],
                                    "tool_name": tool.get("name", "unknown"),
                                },
                            )
                        )
                if depth < 64:
                    stack.extend(
                        (child, f"{path}.{key}", depth + 1)
                        for key, child in value.items()
                        if isinstance(child, (dict, list))
                    )
            elif isinstance(value, list) and depth < 64:
                stack.extend(
                    (child, f"{path}[{index}]", depth + 1)
                    for index, child in enumerate(value)
                    if isinstance(child, (dict, list))
                )
        return findings

    @staticmethod
    def _classify_ref(ref: str) -> Optional[tuple[str, str]]:
        """Return severity and location class; local fragments need no finding."""
        if ref.startswith("#"):
            return None
        try:
            parsed = urlsplit(ref)
            host = parsed.hostname
        except ValueError:
            return "INFO", "malformed"
        if parsed.scheme == "file":
            return "HIGH", "local-file"
        if parsed.scheme in ("http", "https") or parsed.netloc:
            if host:
                try:
                    address = ipaddress.ip_address(host)
                except ValueError:
                    address = None
                if (
                    host.lower() == "localhost"
                    or host.lower().endswith(".localhost")
                    or host.lower().endswith(".local")
                    or (address is not None and not address.is_global)
                ):
                    return "HIGH", "private-network"
            return "MEDIUM", "external-network"
        if parsed.scheme:
            return "INFO", "non-HTTP URI"
        return "INFO", "relative"
