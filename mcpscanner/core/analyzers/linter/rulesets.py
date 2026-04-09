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
"""Predefined rulesets for the MCP schema linter."""

from __future__ import annotations

from typing import Dict, Optional

from .finding import LintSeverity
from .rule import RuleRegistry
from .rules import ALL_RULES

QUALITY_RULE_IDS = frozenset({
    "tool-has-description",
    "tool-description-min-length",
    "tool-description-not-name",
    "tool-schema-properties-have-descriptions",
    "tool-schema-has-examples",
    "tool-output-schema-defined",
    "tool-description-no-html",
    "prompt-has-description",
    "prompt-description-min-length",
    "prompt-argument-has-description",
    "resource-has-description",
})


def build_registry(
    ruleset: str = "recommended",
    overrides: Optional[Dict[str, str]] = None,
) -> RuleRegistry:
    """Build a RuleRegistry for a named ruleset with optional per-rule overrides.

    Rulesets:
      - ``recommended``: all rules at default severities
      - ``strict``: all rules; ``info`` promoted to ``warning``
      - ``quality``: only documentation/completeness rules
    """
    registry = RuleRegistry()
    registry.register_all(ALL_RULES)

    if ruleset == "quality":
        for rule_id in registry.all_rule_ids:
            if rule_id not in QUALITY_RULE_IDS:
                registry.disable(rule_id)
    elif ruleset == "strict":
        for rule_id in registry.all_rule_ids:
            rule = registry.get_rule(rule_id)
            if rule and rule.severity == LintSeverity.INFO:
                registry.set_severity(rule_id, LintSeverity.WARNING)

    if overrides:
        for rule_id, action in overrides.items():
            if action == "off":
                registry.disable(rule_id)
            else:
                try:
                    registry.set_severity(rule_id, LintSeverity(action))
                except ValueError:
                    pass

    return registry
