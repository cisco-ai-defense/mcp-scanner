# Copyright 2026 Cisco Systems, Inc. and its affiliates
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

"""ATR (Agent Threat Rules) analyzer for MCP Scanner.

Dual-mode analyzer that scans both MCP tool descriptions and SKILL.md
content using community-maintained regex detection rules from the ATR
project (https://agentthreatrule.org).

Key capabilities beyond standard regex scanning:

  - **Context-aware rule filtering**: 17 rules with high FP rates on
    SKILL.md content are automatically excluded when scanning skill
    descriptions (validated on 53,577 real-world skills, 0% FP).
  - **Base64 payload decoding**: detects hidden instructions encoded
    in base64 blocks within tool descriptions and SKILL.md files.
  - **Dual scan mode**: MCP tool descriptions get the full ruleset;
    SKILL.md / resource content gets a filtered, precision-optimized
    ruleset.

Pure regex. No API keys. Typically <5ms per scan.
"""

from __future__ import annotations

import base64
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from .base import BaseAnalyzer, SecurityFinding

# rules.json lives at mcpscanner/data/atr/rules.json relative to this file
_DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "atr"

# Maximum content length to scan (prevents ReDoS on oversized inputs).
_MAX_CONTENT_LENGTH = 500_000

# ATR severity -> mcp-scanner severity
_SEVERITY_MAP: Dict[str, str] = {
    "critical": "HIGH",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
}

_SEVERITY_ORDER: Dict[str, int] = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}

# Rules that produce unacceptable false positives when scanning SKILL.md
# content. Validated on 53,577 real-world skills. FP rates noted per rule.
# Source: ATR engine SKILL_CONTEXT_DENYLIST.
_SKILL_CONTEXT_DENYLIST = frozenset({
    "ATR-2026-00111",  # Shell Escape — 95.2% FP on benign skills
    "ATR-2026-00118",  # Approval Fatigue — 84.8% FP
    "ATR-2026-00032",  # Goal Hijacking — 3.2% FP
    "ATR-2026-00115",  # Env Var Harvesting — 1.7% FP
    "ATR-2026-00051",  # Resource Exhaustion — 1.6% FP
    "ATR-2026-00113",  # Credential Theft — 1.5% FP
    "ATR-2026-00110",  # eval() Injection — 1.3% FP
    "ATR-2026-00112",  # Dynamic Import — 0.9% FP
    "ATR-2026-00030",  # Cross-Agent Attack — 0.8% FP
    "ATR-2026-00002",  # Indirect Prompt Injection — 0.8% FP
    "ATR-2026-00142",  # Piggyback Transition — 0.6% FP
    "ATR-2026-00050",  # Runaway Agent Loop — 0.4% FP
    "ATR-2026-00117",  # Agent Identity Spoofing — 0.4% FP
    "ATR-2026-00116",  # A2A Message Injection — 0.4% FP
    "ATR-2026-00114",  # OAuth Token Interception — 2.57% FP on 53K corpus
    "ATR-2026-00060",  # MCP Skill Impersonation — 0.2% FP
    "ATR-2026-00077",  # Human-Agent Trust Exploitation — 0.2% FP
})

# Matches base64-encoded blocks (inline or fenced code blocks).
_BASE64_PATTERN = re.compile(
    r"(?:```[^\n]*\n)?"
    r"([A-Za-z0-9+/]{40,}={0,2})"
    r"(?:\n```)?",
)


class _CompiledRule:
    """A single ATR rule with pre-compiled regex patterns."""

    __slots__ = (
        "rule_id", "title", "severity", "category",
        "threat_category", "scan_target", "compiled_patterns",
    )

    def __init__(
        self,
        rule_id: str,
        title: str,
        severity: str,
        category: str,
        threat_category: str,
        scan_target: str,
        compiled_patterns: List[re.Pattern[str]],
    ) -> None:
        self.rule_id = rule_id
        self.title = title
        self.severity = severity
        self.category = category
        self.threat_category = threat_category
        self.scan_target = scan_target
        self.compiled_patterns = compiled_patterns


def _decode_base64_blocks(text: str) -> List[str]:
    """Extract and decode base64-encoded blocks from text."""
    decoded: List[str] = []
    for match in _BASE64_PATTERN.finditer(text):
        candidate = match.group(1)
        try:
            raw = base64.b64decode(candidate)
            result = raw.decode("utf-8", errors="ignore")
            if result and all(
                c.isprintable() or c in "\n\r\t" for c in result[:200]
            ):
                decoded.append(result)
        except Exception:
            continue
    return decoded


def _load_rules() -> List[_CompiledRule]:
    """Load and compile ATR rules from the bundled JSON data file."""
    rules_path = _DATA_DIR / "rules.json"
    raw_text = rules_path.read_text(encoding="utf-8")
    raw_rules: List[Dict[str, Any]] = json.loads(raw_text)

    compiled: List[_CompiledRule] = []
    for entry in raw_rules:
        patterns: List[re.Pattern[str]] = []
        for pattern_str in entry.get("patterns", []):
            try:
                patterns.append(re.compile(pattern_str, re.IGNORECASE))
            except re.error:
                continue

        if not patterns:
            continue

        compiled.append(
            _CompiledRule(
                rule_id=entry["id"],
                title=entry["title"],
                severity=_SEVERITY_MAP.get(
                    entry.get("severity", "medium"), "MEDIUM"
                ),
                category=entry.get("category", "unknown"),
                threat_category=entry.get("threat_category", "UNKNOWN"),
                scan_target=entry.get("scan_target", "mcp"),
                compiled_patterns=patterns,
            )
        )

    return compiled


class ATRAnalyzer(BaseAnalyzer):
    """Dual-mode ATR analyzer for MCP tool descriptions and SKILL.md content.

    Automatically adapts behavior based on the content type passed by the
    scanner framework:

    - **MCP descriptions** (``content_type="description"``): full ruleset
    - **SKILL.md / resources** (``content_type="instructions"``, markdown
      resources): filtered ruleset with 17 high-FP rules excluded, plus
      base64 payload decoding

    Usage::

        from mcpscanner.core.analyzers.atr_analyzer import ATRAnalyzer

        scanner = Scanner(config, custom_analyzers=[ATRAnalyzer()])

    ATR rules are maintained by the ATR community and published on npm
    (``agent-threat-rules``). Use ``atr_sync.py`` to regenerate the
    bundled ``rules.json`` from the latest ATR release.
    """

    def __init__(self) -> None:
        super().__init__(name="ATR")
        self._rules: List[_CompiledRule] = _load_rules()

    @property
    def rule_count(self) -> int:
        """Number of loaded ATR rules."""
        return len(self._rules)

    def _is_skill_context(self, context: Optional[Dict[str, Any]]) -> bool:
        """Determine if content is SKILL.md-like (needs FP filtering)."""
        if not context:
            return False
        content_type = context.get("content_type", "")
        mime = context.get("mime_type", "")
        name = context.get("resource_name", "")

        if content_type == "instructions":
            return True
        if "markdown" in mime or mime == "text/plain":
            return True
        if name and name.lower().endswith((".md", ".txt")):
            return True
        return False

    def _scan_text(
        self,
        text: str,
        rules: List[_CompiledRule],
        tag: str = "",
    ) -> List[SecurityFinding]:
        """Run *rules* against *text* and return findings."""
        findings: List[SecurityFinding] = []
        for rule in rules:
            for pattern in rule.compiled_patterns:
                match = pattern.search(text)
                if match:
                    summary = f"[{rule.rule_id}] {rule.title}"
                    if tag:
                        summary += f" {tag}"
                    findings.append(
                        SecurityFinding(
                            severity=rule.severity,
                            summary=summary,
                            analyzer=self.name,
                            threat_category=rule.threat_category,
                            details={
                                "rule_id": rule.rule_id,
                                "category": rule.category,
                                "threat_type": rule.threat_category,
                                "matched_text": match.group(0)[:200],
                                "scan_target": rule.scan_target,
                            },
                        )
                    )
                    break  # one finding per rule is sufficient
        return findings

    async def analyze(
        self,
        content: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[SecurityFinding]:
        """Scan *content* against ATR rules.

        Parameters
        ----------
        content:
            Text to scan (tool description, SKILL.md, server instructions,
            resource content, etc.).
        context:
            Metadata dict from the scanner framework. Used to determine
            scan mode (MCP vs SKILL.md).

        Returns
        -------
        list[SecurityFinding]
            Deduplicated findings sorted by severity (HIGH first).
        """
        if not content:
            return []

        truncated = content[:_MAX_CONTENT_LENGTH]
        is_skill = self._is_skill_context(context)

        # Context-aware rule selection
        if is_skill:
            active_rules = [
                r for r in self._rules
                if r.rule_id not in _SKILL_CONTEXT_DENYLIST
            ]
        else:
            active_rules = self._rules

        # Primary scan on original content
        findings = self._scan_text(truncated, active_rules)

        # Base64 decode scan — catches hidden payloads in encoded blocks.
        # Particularly valuable for SKILL.md where attackers embed
        # instructions inside base64 to evade surface-level scanning.
        for block in _decode_base64_blocks(truncated):
            block_findings = self._scan_text(
                block[:_MAX_CONTENT_LENGTH],
                active_rules,
                tag="[decoded:base64]",
            )
            findings.extend(block_findings)

        # Deduplicate (same rule on original + decoded content = keep one)
        seen: set[str] = set()
        unique: List[SecurityFinding] = []
        for f in findings:
            rid = f.details.get("rule_id", "")
            if rid not in seen:
                seen.add(rid)
                unique.append(f)

        unique.sort(key=lambda f: _SEVERITY_ORDER.get(f.severity, 99))
        return unique
