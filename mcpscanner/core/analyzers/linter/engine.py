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
"""Lint engine — orchestrates rules against MCP schema data."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from .config import LintConfig
from .finding import LintFinding, LintSeverity, LintSummary
from .rule import RuleRegistry
from .rulesets import build_registry

logger = logging.getLogger(__name__)


class LintEngine:
    """Run lint rules against MCP tools, prompts, and resources."""

    def __init__(
        self,
        config: Optional[LintConfig] = None,
        ruleset: str = "recommended",
        registry: Optional[RuleRegistry] = None,
    ):
        cfg = config or LintConfig.default()
        effective_ruleset = ruleset if ruleset != "recommended" else cfg.extends
        self.registry = registry or build_registry(
            ruleset=effective_ruleset,
            overrides=cfg.rules or None,
        )

    def lint(
        self,
        tools: Optional[List[Dict[str, Any]]] = None,
        prompts: Optional[List[Dict[str, Any]]] = None,
        resources: Optional[List[Dict[str, Any]]] = None,
        target: str = "",
    ) -> LintSummary:
        """Run all active rules and return a LintSummary."""
        tools = tools or []
        prompts = prompts or []
        resources = resources or []

        all_findings: List[LintFinding] = []
        rules_that_fired: set[str] = set()
        context: Dict[str, Any] = {"target": target}

        for tool in tools:
            for rule in self.registry.get_active_rules(category="tool"):
                findings = rule.check(tool, context)
                if findings:
                    rules_that_fired.add(rule.id)
                all_findings.extend(findings)

        for prompt in prompts:
            for rule in self.registry.get_active_rules(category="prompt"):
                findings = rule.check(prompt, context)
                if findings:
                    rules_that_fired.add(rule.id)
                all_findings.extend(findings)

        for resource in resources:
            for rule in self.registry.get_active_rules(category="resource"):
                findings = rule.check(resource, context)
                if findings:
                    rules_that_fired.add(rule.id)
                all_findings.extend(findings)

        server_data: Dict[str, Any] = {
            "tools": tools,
            "prompts": prompts,
            "resources": resources,
        }
        for rule in self.registry.get_active_rules(category="server"):
            findings = rule.check(server_data, context)
            if findings:
                rules_that_fired.add(rule.id)
            all_findings.extend(findings)

        all_findings.sort(key=lambda f: f.severity.rank)

        rules_checked = self.registry.active_count
        rules_failed = len(rules_that_fired)

        sev_counts: Dict[str, int] = {}
        cat_counts: Dict[str, int] = {}
        for f in all_findings:
            sev_counts[f.severity.value] = sev_counts.get(f.severity.value, 0) + 1
            cat_counts[f.category] = cat_counts.get(f.category, 0) + 1

        return LintSummary(
            target=target,
            tools_scanned=len(tools),
            prompts_scanned=len(prompts),
            resources_scanned=len(resources),
            rules_checked=rules_checked,
            rules_passed=rules_checked - rules_failed,
            rules_failed=rules_failed,
            total_findings=len(all_findings),
            findings_by_severity=sev_counts,
            findings_by_category=cat_counts,
            findings=all_findings,
        )
