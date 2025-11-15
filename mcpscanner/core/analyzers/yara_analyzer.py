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

"""YARA Analyzer module for MCP Scanner SDK.

This module contains the YARA analyzer class for analyzing MCP tools using YARA rules.
"""

from typing import Any, Dict, List, Optional, Union
from importlib.resources.abc import Traversable
from pathlib import Path

import yara

from ...config.constants import MCPScannerConstants
from ...threats.threats import YARA_THREAT_MAPPING
from .base import BaseAnalyzer, SecurityFinding


class YaraAnalyzer(BaseAnalyzer):
    """Analyzer class for analyzing MCP tools using YARA rules.

    This class provides functionality to analyze MCP tool descriptions and parameters
    using YARA rules for pattern matching and returns security findings directly.

    Example:
        >>> from mcpscanner.analyzers import YaraAnalyzer
        >>> analyzer = YaraAnalyzer(rules_dir="/path/to/rules")
        >>> findings = analyzer.analyze("Content to analyze")
        >>> if not findings:
        ...     pass  # Tool is safe
        ... else:
        ...     pass  # Found security findings
    """

    def __init__(
        self, config=None, rules_dir: Optional[Union[str, Path, Traversable]] = None
    ):
        """Initialize a new YaraAnalyzer instance.

        Args:
            config: Configuration object (not used by YARA analyzer but kept for consistency).
            rules_dir: Optional custom path to YARA rules directory. If None, uses default location.

        Raises:
            FileNotFoundError: If the rules directory does not exist or contains no rule files.
            yara.Error: If there is a syntax error in any of the rule files.
        """
        super().__init__("YARA")

        if rules_dir:
            if isinstance(rules_dir, str):
                self._rules_dir = Path(rules_dir)
            else:
                self._rules_dir = rules_dir
            self.logger.debug(
                f'Using custom YARA rules directory: rules_dir="{self._rules_dir}"'
            )
        else:
            self._rules_dir = MCPScannerConstants.get_yara_rules_path()
            self.logger.debug(
                f'Using default YARA rules directory: rules_dir="{self._rules_dir}"'
            )

        self._rules = self._load_rules()

    def _load_rules(self) -> yara.Rules:
        """Load and compile all YARA rules from the rules directory.

        Returns:
            yara.Rules: The compiled YARA rules.

        Raises:
            FileNotFoundError: If the rules directory does not exist or contains no rule files.
            yara.Error: If there is a syntax error in any of the rule files.
        """
        rule_sources = {}

        if not self._rules_dir.is_dir():
            self.logger.error(f"YARA rules directory not found at: {self._rules_dir}")
            raise FileNotFoundError(
                f"YARA rules directory not found at: {self._rules_dir}"
            )

        for item in self._rules_dir.iterdir():
            if item.name.endswith((".yara", ".yar")):
                self.logger.debug(f"Found rule file: {item.name}")
                rule_sources[item.name] = item.read_text(encoding="utf-8")

        if not rule_sources:
            self.logger.error(f"No YARA rule files found in '{self._rules_dir}'")
            raise FileNotFoundError(f"No YARA rule files found in '{self._rules_dir}'")

        self.logger.debug(
            f"Compiling {len(rule_sources)} rule file(s): {list(rule_sources.keys())}"
        )
        try:
            rules = yara.compile(sources=rule_sources)
            self.logger.debug("YARA rules compiled successfully")
            return rules
        except yara.Error as e:
            self.logger.error(f"Error compiling YARA rules: {e}")
            raise

    async def analyze(
        self, content: str, context: Optional[Dict[str, Any]] = None
    ) -> List[SecurityFinding]:
        """Analyze the provided content using YARA rules and return security findings.

        Args:
            content (str): The content to analyze.
            context (Optional[Dict[str, Any]]): Additional context for analysis.
                Can include 'content_type' (e.g., 'description', 'parameters') for better reporting.

        Returns:
            List[SecurityFinding]: The security findings found during the analysis.
        """
        findings = []
        tool_name = context.get("tool_name", "unknown") if context else "unknown"
        content_type = context.get("content_type", "content") if context else "content"

        if not content:
            return findings

        try:
            matches = self._rules.match(data=content)
            rule_names = []  # Collect rule names for summary

            # First pass: collect all rule names
            for match in matches:
                rule_name = match.rule
                if rule_name not in rule_names:
                    rule_names.append(rule_name)

            # Create summary with rule count and names
            if len(rule_names) == 1:
                summary = f"Detected 1 threat: {', '.join([name.replace('_', ' ') for name in rule_names])}"
            else:
                summary = f"Detected {len(rule_names)} threats: {', '.join([name.replace('_', ' ') for name in rule_names])}"

            # Second pass: create findings
            for match in matches:
                rule_name = match.rule
                description = match.meta.get("description", "")
                classification = match.meta.get("classification", "unknown")
                threat_type = match.meta.get("threat_type", "unknown")

                # Use centralized threat mapping (includes severity)
                threat_info = YARA_THREAT_MAPPING.get(threat_type)
                
                if threat_info:
                    # Severity already included in threat_info mapping
                    mapping = {
                        "category": threat_info["threat_category"],
                        "severity": threat_info["severity"],
                    }
                else:
                    mapping = {"severity": "UNKNOWN", "category": "N/A"}

                findings.append(
                    SecurityFinding(
                        severity=mapping["severity"],
                        summary=summary,
                        analyzer="YARA",
                        threat_category=mapping["category"],
                        details={
                            "tool_name": tool_name,
                            "threat_type": threat_type,
                            "evidence": f"Content matches YARA rule '{rule_name}': {description}",
                            "raw_response": {
                                "rule": rule_name,
                                "classification": classification,
                                "description": description,
                                "threat_type": threat_type,
                            },
                            "content_type": content_type,
                        },
                    )
                )

        except Exception as e:
            self.logger.error(f"YARA analysis failed for tool '{tool_name}': {e}")
            raise

        return findings
