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

"""Base analyzer module for MCP Scanner SDK.

This module contains the base analyzer interface and common classes.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from ...utils.logging_config import get_logger
from ...threats.threats import ThreatMapping


class SecurityFinding:
    """Represents a single security finding from an analyzer.

    Attributes:
        severity (str): The severity level: "HIGH", "MEDIUM", "LOW", or "INFO".
        summary (str): A summary description of the security finding.
        threat_category (str): Standardized threat category.
        analyzer (str): The name of the analyzer that found the security finding.
        details (Optional[Dict[str, Any]]): Additional details about the security finding.
        mcp_taxonomy (Optional[Dict[str, Any]]): MCP Taxonomy classification information.
    """

    def __init__(
        self,
        severity: str,
        summary: str,
        analyzer: str,
        threat_category: str,
        details: Optional[Dict[str, Any]] = None,
    ):
        """Initialize a new SecurityFinding instance.

        Args:
            severity (str): The severity level ("HIGH", "MEDIUM", "LOW", "INFO", "SAFE", "UNKNOWN").
            summary (str): A summary description of the security finding.
            analyzer (str): The name of the analyzer that found the security finding.
            threat_category (str): Standardized threat category.
            details (Optional[Dict[str, Any]]): Additional details about the security finding.
        """
        # Validate and normalize inputs
        self.severity = self._normalize_level(
            severity, ["HIGH", "MEDIUM", "LOW", "INFO", "SAFE", "UNKNOWN"], "UNKNOWN"
        )
        self.summary = summary
        self.threat_category = threat_category
        self.analyzer = analyzer
        self.details = details or {}
        
        # Enrich with MCP Taxonomy information
        self.mcp_taxonomy = self._get_mcp_taxonomy()

    def _normalize_level(
        self, level: str, valid_levels: List[str], default: str
    ) -> str:
        """Normalize a level string to uppercase and validate against allowed values.

        Args:
            level: The level to normalize.
            valid_levels: List of valid level values.
            default: Default value if level is invalid.

        Returns:
            Normalized and validated level string.
        """
        if not level:
            return default

        normalized = level.upper()
        return normalized if normalized in valid_levels else default
    
    def _get_mcp_taxonomy(self) -> Optional[Dict[str, Any]]:
        """Get MCP Taxonomy classification for this finding.
        
        Returns:
            Dictionary with MCP Taxonomy information or None if not found.
        """
        try:
            # Map analyzer names to threat mapping keys
            analyzer_map = {
                "LLM": "llm",
                "YARA": "yara",
                "API": "ai_defense",
                "BEHAVIORAL": "behavioral",
            }
            
            # Check if this is a built-in analyzer
            analyzer_key = analyzer_map.get(self.analyzer.upper())
            
            # If not a built-in analyzer, check if it's a custom analyzer using AI Defense classifications
            # Custom analyzers that use AI Defense threat types should have threat_type in details
            if not analyzer_key and self.details and "threat_type" in self.details:
                # Try to map to ai_defense if the threat_type matches AI Defense threat names
                threat_type = self.details.get("threat_type", "").upper()
                # Check if this threat exists in AI Defense threats
                try:
                    ThreatMapping.get_threat_mapping("ai_defense", threat_type)
                    analyzer_key = "ai_defense"
                except ValueError:
                    # Not an AI Defense threat, return None
                    return None
            
            if not analyzer_key:
                return None
            
            # For all analyzers, try to use threat_type from details for accurate taxonomy lookup
            threat_name = self.threat_category
            if self.details:
                # Try to get the threat_type from details (original classification name)
                threat_type = self.details.get("threat_type")
                if threat_type:
                    threat_name = threat_type
                elif analyzer_key == "yara":
                    # Fallback for YARA: try to get from raw_response
                    raw_response = self.details.get("raw_response", {})
                    rule_threat_type = raw_response.get("threat_type", "")
                    if rule_threat_type:
                        threat_name = rule_threat_type
            
            if not threat_name:
                return None
            
            # Look up in threat mapping
            mapping = ThreatMapping.get_threat_mapping(analyzer_key, threat_name)
            return {
                "scanner_category": mapping.get("scanner_category"),
                "aitech": mapping.get("aitech"),
                "aitech_name": mapping.get("aitech_name"),
                "aisubtech": mapping.get("aisubtech"),
                "aisubtech_name": mapping.get("aisubtech_name"),
                "description": mapping.get("description"),
            }
        except (ValueError, KeyError, AttributeError) as e:
            # If threat not found in mapping, return None
            # Silently fail to avoid breaking the scan
            return None

    def __str__(self) -> str:
        return f"{self.severity}: {self.threat_category} - {self.summary} (analyzer: {self.analyzer})"


class BaseAnalyzer(ABC):
    """Base class for all analyzers.

    This abstract class defines the interface that all analyzers must implement
    and provides shared functionality for logging, validation, and error handling.
    """

    def __init__(self, name: str):
        """Initialize the base analyzer.

        Args:
            name: The name of the analyzer for logging and identification.
        """
        self.name = name
        self.logger = get_logger(f"{__name__}.{name}")

    def validate_content(self, content: str) -> None:
        """Validate that content is suitable for analysis.

        Args:
            content: The content to validate.

        Raises:
            ValueError: If content is invalid.
        """
        if not content or not content.strip():
            raise ValueError("Content cannot be empty or whitespace-only")

        if len(content) > 100000:  # 100KB limit
            self.logger.warning(
                f"Content is very large ({len(content)} chars), analysis may be slow"
            )

    def create_security_finding(
        self,
        severity: str,
        summary: str,
        threat_category: str,
        confidence: str = "MEDIUM",
        details: Optional[Dict[str, Any]] = None,
    ) -> SecurityFinding:
        """Create a security finding with this analyzer's name and standardized format.

        Args:
            severity: The severity level ("HIGH", "MEDIUM", "LOW", "INFO", "SAFE", "UNKNOWN").
            summary: Brief description of the security finding.
            threat_category: Standardized threat category.
            confidence: The confidence level ("HIGH", "MEDIUM", "LOW").
            details: Additional details about the security finding.

        Returns:
            SecurityFinding: The created security finding instance.
        """
        return SecurityFinding(
            severity=severity,
            summary=summary,
            analyzer=self.name,
            threat_category=threat_category,
            details=details,
        )

    async def safe_analyze(
        self, content: str, context: Optional[Dict[str, Any]] = None
    ) -> List[SecurityFinding]:
        """Safely analyze content with validation and error handling.

        Args:
            content: The content to analyze.
            context: Additional context for the analysis.

        Returns:
            List of security findings found, empty list on error.
        """
        try:
            self.validate_content(content)
            # Analysis starting
            findings = await self.analyze(content, context)
            self.logger.debug(
                f"Analysis complete: found {len(findings)} potential threats"
            )
            return findings
        except Exception as e:
            self.logger.error(f"Analysis failed: {e}")
            return []

    @abstractmethod
    async def analyze(
        self, content: str, context: Optional[Dict[str, Any]] = None
    ) -> List[SecurityFinding]:
        """Analyze the provided content and return a list of security findings.

        Args:
            content (str): The content to analyze.
            context (Optional[Dict[str, Any]]): Additional context for the analysis.

        Returns:
            List[SecurityFinding]: The security findings found during the analysis.
        """
        pass
