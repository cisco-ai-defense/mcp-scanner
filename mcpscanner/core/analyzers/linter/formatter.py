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
"""Output formatters for the MCP schema linter."""

from __future__ import annotations

import json
from typing import List

from .finding import LintFinding, LintSeverity, LintSummary


class LintFormatter:
    """Format LintSummary for display."""

    def __init__(self, summary: LintSummary) -> None:
        self.summary = summary

    def format_table(self) -> str:
        """Produce the human-readable table output shown in CLI."""
        lines: List[str] = []
        s = self.summary

        grouped = self._group_by_category(s.findings)

        for category, findings in grouped:
            lines.append(f"{category.title()} Quality")
            header = (
                f"    {'#':>3}  {'SEVERITY':<10}"
                f"{'CODE':<37}"
                f"{'FINDINGS':<40}"
                f"{'RECOMMENDATION':<40}"
                f"{'AFFECTED ITEMS':>14}"
            )
            lines.append(header)
            lines.append("    " + "\u2014" * (len(header) - 4))

            for idx, f in enumerate(findings, 1):
                lines.append(
                    f"    {idx:>3}  {f.severity.value:<10}"
                    f"{f.rule_id:<37}"
                    f"{_truncate(f.message, 38):<40}"
                    f"{_truncate(f.recommendation, 38):<40}"
                    f"{f.affected_items:>14}"
                )

        lines.append("")
        lines.append(self._finding_counts_line(s))
        lines.append(self._category_table(s))

        lines.append("")
        lines.append("=" * 60)
        lines.append(self._summary_block(s))

        return "\n".join(lines)

    def format_summary(self) -> str:
        """Produce a compact summary."""
        s = self.summary
        lines = [
            "=" * 60,
            self._summary_block(s),
            "",
            self._finding_counts_line(s),
        ]
        return "\n".join(lines)

    def format_json(self) -> str:
        """Produce deterministic JSON output for CI/CD pipelines."""
        return json.dumps(self.summary.to_dict(), indent=2, sort_keys=False)

    def format(self, fmt: str = "table") -> str:
        if fmt == "json":
            return self.format_json()
        if fmt == "summary":
            return self.format_summary()
        return self.format_table()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _group_by_category(findings: List[LintFinding]) -> List[tuple]:
        groups: dict[str, List[LintFinding]] = {}
        for f in findings:
            groups.setdefault(f.category, []).append(f)
        order = ["tool", "prompt", "resource", "server"]
        result = []
        for cat in order:
            if cat in groups:
                result.append((cat, groups[cat]))
        for cat in sorted(groups):
            if cat not in order:
                result.append((cat, groups[cat]))
        return result

    @staticmethod
    def _finding_counts_line(s: LintSummary) -> str:
        sev = s.findings_by_severity
        parts = [
            f"{sev.get('error', 0)} Error",
            f"{sev.get('warning', 0)} Warning",
            f"{sev.get('info', 0)} Info",
            f"{sev.get('hint', 0)} Hint",
        ]
        return f"{s.total_findings} Findings ({', '.join(parts)})"

    @staticmethod
    def _category_table(s: LintSummary) -> str:
        cats = s.findings_by_category
        if not cats:
            return ""
        lines = [
            f"  {'#':>3} | {'CATEGORY':<12} | {'ERROR':>5} | {'WARNING':>7} | {'INFO':>4} | {'HINT':>4}",
            "  " + "-" * 55,
        ]
        for idx, (cat, _) in enumerate(sorted(cats.items()), 1):
            cat_findings = [f for f in s.findings if f.category == cat]
            by_sev = {}
            for f in cat_findings:
                by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
            lines.append(
                f"  {idx:>3} | {cat.title():<12} "
                f"| {by_sev.get('error', 0):>5} "
                f"| {by_sev.get('warning', 0):>7} "
                f"| {by_sev.get('info', 0):>4} "
                f"| {by_sev.get('hint', 0):>4}"
            )
        return "\n".join(lines)

    @staticmethod
    def _summary_block(s: LintSummary) -> str:
        total_scanned = s.tools_scanned + s.prompts_scanned + s.resources_scanned
        parts = []
        if s.tools_scanned:
            parts.append(f"{s.tools_scanned} tools")
        if s.prompts_scanned:
            parts.append(f"{s.prompts_scanned} prompts")
        if s.resources_scanned:
            parts.append(f"{s.resources_scanned} resources")
        scanned_str = ", ".join(parts) if parts else "0 items"

        pct = (
            f"{s.rules_passed / s.rules_checked * 100:.0f}%"
            if s.rules_checked
            else "N/A"
        )
        lines = [
            "Summary",
            f"  Scanned:       {scanned_str}",
            f"  Rules checked: {s.rules_checked}",
            f"  Rules passed:  {s.rules_passed} ({pct})",
            f"  Rules failed:  {s.rules_failed}",
            f"  Total issues:  {s.total_findings}",
        ]
        return "\n".join(lines)


def _truncate(text: str, max_len: int) -> str:
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."
