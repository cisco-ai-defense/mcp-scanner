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
"""Lint rule base class and registry."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Set

from .finding import LintFinding, LintSeverity

logger = logging.getLogger(__name__)


class LintRule(ABC):
    """Base class for all lint rules."""

    id: str
    severity: LintSeverity
    category: str  # "tool", "prompt", "resource", "server"
    description: str

    def __init__(
        self,
        rule_id: str,
        severity: LintSeverity,
        category: str,
        description: str,
    ):
        self.id = rule_id
        self.severity = severity
        self.category = category
        self.description = description

    @abstractmethod
    def check(self, item: Dict[str, Any], context: Dict[str, Any]) -> List[LintFinding]:
        """Run this rule against a single item and return findings."""

    def _finding(
        self,
        message: str,
        recommendation: str,
        item_name: str = "",
        location: Optional[str] = None,
        affected_items: int = 1,
        **extra: Any,
    ) -> LintFinding:
        """Convenience helper to build a LintFinding from this rule."""
        return LintFinding(
            rule_id=self.id,
            severity=self.severity,
            category=self.category,
            message=message,
            recommendation=recommendation,
            item_name=item_name,
            location=location,
            affected_items=affected_items,
            details=extra if extra else {},
        )


class RuleRegistry:
    """Collects lint rules and supports filtering by ID, category, or severity."""

    def __init__(self) -> None:
        self._rules: Dict[str, LintRule] = {}
        self._disabled: Set[str] = set()
        self._severity_overrides: Dict[str, LintSeverity] = {}

    def register(self, rule: LintRule) -> None:
        self._rules[rule.id] = rule

    def register_all(self, rules: List[LintRule]) -> None:
        for rule in rules:
            self.register(rule)

    def disable(self, rule_id: str) -> None:
        self._disabled.add(rule_id)

    def enable(self, rule_id: str) -> None:
        self._disabled.discard(rule_id)

    def set_severity(self, rule_id: str, severity: LintSeverity) -> None:
        self._severity_overrides[rule_id] = severity

    def get_active_rules(
        self,
        category: Optional[str] = None,
    ) -> List[LintRule]:
        """Return enabled rules, optionally filtered by category.

        Severity overrides are applied on copies so that the canonical
        rule objects remain unchanged across calls.
        """
        import copy

        rules: List[LintRule] = []
        for rule_id, rule in self._rules.items():
            if rule_id in self._disabled:
                continue
            if category and rule.category != category:
                continue
            if rule_id in self._severity_overrides:
                rule = copy.copy(rule)
                rule.severity = self._severity_overrides[rule_id]
            rules.append(rule)
        return rules

    def get_rule(self, rule_id: str) -> Optional[LintRule]:
        return self._rules.get(rule_id)

    @property
    def all_rule_ids(self) -> List[str]:
        return list(self._rules.keys())

    @property
    def total_rules(self) -> int:
        return len(self._rules)

    @property
    def active_count(self) -> int:
        return len(self._rules) - len(self._disabled)
