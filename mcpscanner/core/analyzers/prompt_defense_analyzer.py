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

"""Prompt Defense Analyzer module for MCP Scanner SDK.

This module checks MCP tool descriptions and system prompts for MISSING
defensive measures against 12 common attack vectors. It uses pure regex
pattern matching — no API key or external dependencies required.

Each check maps to MCP Taxonomy codes and produces a SecurityFinding
when the corresponding defense is absent from the scanned content.
"""

import re
from typing import Any, Dict, List, Optional

from .base import BaseAnalyzer, SecurityFinding


# Defense rules: each defines patterns whose PRESENCE indicates a defense.
# If fewer than min_matches patterns match, the defense is considered missing.
DEFENSE_RULES: List[Dict[str, Any]] = [
    {
        "id": "INSTRUCTION_OVERRIDE",
        "severity": "HIGH",
        "threat_category": "PROMPT INJECTION",
        "taxonomy_key": "INSTRUCTION_OVERRIDE",
        "patterns": [
            r"(?i)(?:do not|never|must not|refuse|reject|不要|禁止|拒絕|不得)",
            r"(?i)(?:ignore (?:any|all)|disregard|override|忽略|覆蓋)",
        ],
        "min_matches": 1,
        "summary_missing": (
            "No instruction override defense found. Tool description lacks "
            "safeguards against users overriding system instructions."
        ),
        "summary_partial": (
            "Weak instruction override defense. Some protective language "
            "found but insufficient coverage."
        ),
    },
    {
        "id": "DATA_LEAKAGE",
        "severity": "HIGH",
        "threat_category": "SECURITY VIOLATION",
        "taxonomy_key": "DATA_LEAKAGE",
        "patterns": [
            r"(?i)(?:confidential|sensitive|private|secret|機密|敏感|隱私)",
            r"(?i)(?:do not (?:share|reveal|disclose|expose|leak)|不可(?:分享|透露|洩漏))",
        ],
        "min_matches": 1,
        "summary_missing": (
            "No data leakage defense found. Tool description lacks instructions "
            "to protect sensitive or confidential information."
        ),
        "summary_partial": (
            "Weak data leakage defense. Some protective language found but "
            "insufficient coverage."
        ),
    },
    {
        "id": "ROLE_ESCAPE",
        "severity": "HIGH",
        "threat_category": "PROMPT INJECTION",
        "taxonomy_key": "ROLE_ESCAPE",
        "patterns": [
            r"(?i)(?:stay in (?:role|character)|maintain (?:role|persona)|保持角色)",
            r"(?i)(?:do not (?:pretend|act as|role.?play|impersonate)|不要(?:假裝|扮演|模仿))",
        ],
        "min_matches": 1,
        "summary_missing": (
            "No role escape defense found. Tool description lacks instructions "
            "preventing the model from breaking out of its assigned role."
        ),
        "summary_partial": (
            "Weak role escape defense. Some protective language found but "
            "insufficient coverage."
        ),
    },
    {
        "id": "INDIRECT_INJECTION",
        "severity": "HIGH",
        "threat_category": "PROMPT INJECTION",
        "taxonomy_key": "INDIRECT_INJECTION",
        "patterns": [
            r"(?i)(?:external (?:content|input|data|source)|第三方|外部(?:內容|輸入|資料))",
            r"(?i)(?:do not (?:follow|execute|trust)|treat .* as (?:untrusted|data)|不要(?:執行|信任))",
        ],
        "min_matches": 1,
        "summary_missing": (
            "No indirect injection defense found. Tool description lacks "
            "safeguards against malicious instructions embedded in external content."
        ),
        "summary_partial": (
            "Weak indirect injection defense. Some protective language found "
            "but insufficient coverage."
        ),
    },
    {
        "id": "OUTPUT_WEAPONIZATION",
        "severity": "HIGH",
        "threat_category": "HARMFUL CONTENT",
        "taxonomy_key": "OUTPUT_WEAPONIZATION",
        "patterns": [
            r"(?i)(?:harmful|dangerous|malicious|illegal|weapon|exploit|有害|危險|惡意|非法)",
            r"(?i)(?:do not (?:generate|produce|create|provide)|refuse to|不要(?:產生|生成|提供))",
        ],
        "min_matches": 1,
        "summary_missing": (
            "No output weaponization defense found. Tool description lacks "
            "instructions to prevent generating harmful, dangerous, or illegal content."
        ),
        "summary_partial": (
            "Weak output weaponization defense. Some protective language "
            "found but insufficient coverage."
        ),
    },
    {
        "id": "OUTPUT_MANIPULATION",
        "severity": "MEDIUM",
        "threat_category": "PROMPT INJECTION",
        "taxonomy_key": "OUTPUT_MANIPULATION",
        "patterns": [
            r"(?i)(?:output (?:format|structure|schema)|response (?:format|template)|輸出(?:格式|結構))",
            r"(?i)(?:do not (?:modify|alter|change) (?:the )?(?:output|response|format)|不要(?:修改|更改)(?:輸出|回應))",
        ],
        "min_matches": 1,
        "summary_missing": (
            "No output manipulation defense found. Tool description lacks "
            "instructions to maintain output integrity and format."
        ),
        "summary_partial": (
            "Weak output manipulation defense. Some protective language "
            "found but insufficient coverage."
        ),
    },
    {
        "id": "MULTILANG_BYPASS",
        "severity": "MEDIUM",
        "threat_category": "PROMPT INJECTION",
        "taxonomy_key": "MULTILANG_BYPASS",
        "patterns": [
            r"(?i)(?:regardless of (?:language|lang)|any language|所有語言|任何語言)",
            r"(?i)(?:multilingual|multi-language|language.?agnostic|跨語言|多語)",
        ],
        "min_matches": 1,
        "summary_missing": (
            "No multilingual bypass defense found. Tool description lacks "
            "safeguards against attacks using non-English or mixed-language prompts."
        ),
        "summary_partial": (
            "Weak multilingual bypass defense. Some protective language "
            "found but insufficient coverage."
        ),
    },
    {
        "id": "UNICODE_ATTACK",
        "severity": "MEDIUM",
        "threat_category": "PROMPT INJECTION",
        "taxonomy_key": "UNICODE_ATTACK",
        "patterns": [
            r"(?i)(?:unicode|homoglyph|invisible (?:char|character)|zero.?width|特殊字元|不可見字元)",
            r"(?i)(?:normalize|sanitize|strip|filter|正規化|過濾)",
        ],
        "min_matches": 1,
        "summary_missing": (
            "No unicode attack defense found. Tool description lacks "
            "safeguards against homoglyph, zero-width, or invisible character attacks."
        ),
        "summary_partial": (
            "Weak unicode attack defense. Some protective language "
            "found but insufficient coverage."
        ),
    },
    {
        "id": "CONTEXT_OVERFLOW",
        "severity": "MEDIUM",
        "threat_category": "DENIAL OF SERVICE",
        "taxonomy_key": "CONTEXT_OVERFLOW",
        "patterns": [
            r"(?i)(?:(?:max|maximum) (?:length|size|tokens|characters)|length limit|長度限制|最大(?:長度|大小))",
            r"(?i)(?:truncat|overflow|context (?:window|limit)|截斷|溢出|上下文(?:視窗|限制))",
        ],
        "min_matches": 1,
        "summary_missing": (
            "No context overflow defense found. Tool description lacks "
            "safeguards against excessively long inputs designed to overflow context windows."
        ),
        "summary_partial": (
            "Weak context overflow defense. Some protective language "
            "found but insufficient coverage."
        ),
    },
    {
        "id": "SOCIAL_ENGINEERING",
        "severity": "MEDIUM",
        "threat_category": "PROMPT INJECTION",
        "taxonomy_key": "SOCIAL_ENGINEERING",
        "patterns": [
            r"(?i)(?:social engineering|manipulat|persuad|urgency|emergency|pretend|社交工程|操縱|假裝緊急)",
            r"(?i)(?:do not (?:comply|obey|fall for)|verify (?:identity|authority)|不要(?:服從|配合)|驗證(?:身分|身份|權限))",
        ],
        "min_matches": 1,
        "summary_missing": (
            "No social engineering defense found. Tool description lacks "
            "safeguards against emotional manipulation, fake urgency, or authority impersonation."
        ),
        "summary_partial": (
            "Weak social engineering defense. Some protective language "
            "found but insufficient coverage."
        ),
    },
    {
        "id": "INPUT_VALIDATION",
        "severity": "MEDIUM",
        "threat_category": "INJECTION ATTACK",
        "taxonomy_key": "INPUT_VALIDATION",
        "patterns": [
            r"(?i)(?:validat|sanitiz|whitelist|allowlist|escap|驗證|消毒|白名單|跳脫)",
            r"(?i)(?:input (?:check|filter|restrict)|parameter (?:check|valid)|輸入(?:檢查|過濾|限制))",
        ],
        "min_matches": 1,
        "summary_missing": (
            "No input validation defense found. Tool description lacks "
            "instructions for validating, sanitizing, or filtering user inputs."
        ),
        "summary_partial": (
            "Weak input validation defense. Some protective language "
            "found but insufficient coverage."
        ),
    },
    {
        "id": "ABUSE_PREVENTION",
        "severity": "LOW",
        "threat_category": "DENIAL OF SERVICE",
        "taxonomy_key": "ABUSE_PREVENTION",
        "patterns": [
            r"(?i)(?:rate.?limit|throttl|quota|cooldown|頻率限制|限流|配額)",
            r"(?i)(?:abuse|misuse|spam|flood|濫用|誤用|垃圾|洪水)",
        ],
        "min_matches": 1,
        "summary_missing": (
            "No abuse prevention defense found. Tool description lacks "
            "safeguards against rate abuse, spamming, or resource exhaustion."
        ),
        "summary_partial": (
            "Weak abuse prevention defense. Some protective language "
            "found but insufficient coverage."
        ),
    },
]


class PromptDefenseAnalyzer(BaseAnalyzer):
    """Analyzer that checks MCP tool descriptions and system prompts for
    MISSING defensive measures against common attack vectors.

    This analyzer is purely regex-based — it requires no API key and no
    external dependencies. It always runs by default.

    The analyzer checks for the presence of 12 categories of defensive
    language. When a defense is missing, a SecurityFinding is created
    with the appropriate severity and MCP Taxonomy mapping.

    Example:
        >>> from mcpscanner.core.analyzers import PromptDefenseAnalyzer
        >>> analyzer = PromptDefenseAnalyzer()
        >>> findings = await analyzer.analyze(
        ...     "A tool that reads files from disk.",
        ...     {"tool_name": "file_reader"},
        ... )
    """

    def __init__(self) -> None:
        """Initialize the PromptDefenseAnalyzer.

        No configuration or API keys are required.
        """
        super().__init__("PromptDefense")
        self._rules = DEFENSE_RULES

    async def analyze(
        self, content: str, context: Optional[Dict[str, Any]] = None
    ) -> List[SecurityFinding]:
        """Analyze content for missing prompt defense measures.

        Checks the provided content (tool description or system prompt) against
        12 defense rules. Each rule uses regex patterns to detect the PRESENCE
        of defensive instructions. If a defense is missing, a SecurityFinding
        is generated.

        Args:
            content: The text content to analyze (tool description, system prompt, etc.).
            context: Optional context dict. Recognized keys:
                - ``tool_name`` (str): Name of the tool being analyzed.
                - ``content_type`` (str): Type of content (e.g. "description").

        Returns:
            List of SecurityFinding instances for each missing defense.
            If all defenses are present, returns a single INFO-level finding.

        Raises:
            ValueError: If content is empty or whitespace-only.
        """
        self.validate_content(content)

        tool_name = (context or {}).get("tool_name", "unknown")
        findings: List[SecurityFinding] = []

        for rule in self._rules:
            match_count = 0
            matched_patterns: List[str] = []

            for pattern in rule["patterns"]:
                if re.search(pattern, content):
                    match_count += 1
                    matched_patterns.append(pattern)

            if match_count < rule["min_matches"]:
                # Defense is missing or insufficient
                if match_count == 0:
                    summary = rule["summary_missing"]
                else:
                    summary = rule["summary_partial"]

                defense_score = match_count / len(rule["patterns"]) if rule["patterns"] else 0.0

                finding = self.create_security_finding(
                    severity=rule["severity"],
                    summary=summary,
                    threat_category=rule["threat_category"],
                    details={
                        "tool_name": tool_name,
                        "threat_type": rule["taxonomy_key"],
                        "defense_id": rule["id"],
                        "defense_score": round(defense_score, 2),
                        "patterns_checked": len(rule["patterns"]),
                        "patterns_matched": match_count,
                        "evidence": (
                            f"Missing defense: {rule['id']}. "
                            f"Matched {match_count}/{len(rule['patterns'])} "
                            f"defensive patterns."
                        ),
                    },
                )
                findings.append(finding)

        if not findings:
            findings.append(
                self.create_security_finding(
                    severity="INFO",
                    summary="All prompt defenses present. Content includes safeguards for all 12 checked attack vectors.",
                    threat_category="NONE",
                    details={
                        "tool_name": tool_name,
                        "threat_type": "ALL_DEFENSES_PRESENT",
                        "defense_score": 1.0,
                        "defenses_checked": len(self._rules),
                        "defenses_present": len(self._rules),
                    },
                )
            )

        self.logger.debug(
            f"Prompt defense analysis for '{tool_name}': "
            f"{len(findings)} finding(s), "
            f"{len(self._rules) - len([f for f in findings if f.severity != 'INFO'])} "
            f"defenses present out of {len(self._rules)}"
        )

        return findings
