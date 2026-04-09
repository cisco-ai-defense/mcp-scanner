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
"""Data model for lint findings and severity levels."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class LintSeverity(str, Enum):
    """Severity levels for lint findings, ordered from most to least severe."""

    ERROR = "error"
    WARNING = "warning"
    INFO = "info"
    HINT = "hint"

    @property
    def rank(self) -> int:
        return {
            LintSeverity.ERROR: 0,
            LintSeverity.WARNING: 1,
            LintSeverity.INFO: 2,
            LintSeverity.HINT: 3,
        }[self]

    def __lt__(self, other: "LintSeverity") -> bool:
        return self.rank < other.rank


@dataclass
class LintFinding:
    """A single finding produced by a lint rule."""

    rule_id: str
    severity: LintSeverity
    category: str
    message: str
    recommendation: str
    item_name: str = ""
    location: Optional[str] = None
    affected_items: int = 1
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "category": self.category,
            "message": self.message,
            "recommendation": self.recommendation,
            "item_name": self.item_name,
            "affected_items": self.affected_items,
        }
        if self.location:
            result["location"] = self.location
        if self.details:
            result["details"] = self.details
        return result


@dataclass
class LintSummary:
    """Aggregated lint results for a scan target."""

    target: str
    tools_scanned: int = 0
    prompts_scanned: int = 0
    resources_scanned: int = 0
    rules_checked: int = 0
    rules_passed: int = 0
    rules_failed: int = 0
    total_findings: int = 0
    findings_by_severity: Dict[str, int] = field(default_factory=dict)
    findings_by_category: Dict[str, int] = field(default_factory=dict)
    findings: List[LintFinding] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "tools_scanned": self.tools_scanned,
            "prompts_scanned": self.prompts_scanned,
            "resources_scanned": self.resources_scanned,
            "rules_checked": self.rules_checked,
            "rules_passed": self.rules_passed,
            "rules_failed": self.rules_failed,
            "total_findings": self.total_findings,
            "findings_by_severity": self.findings_by_severity,
            "findings_by_category": self.findings_by_category,
            "findings": [f.to_dict() for f in self.findings],
        }
