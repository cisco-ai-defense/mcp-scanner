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

"""API Analyzer module for MCP Scanner SDK.

This module contains the API analyzer class for analyzing MCP tools using Cisco AI Defense API.
"""

from typing import Any, Dict, List, Optional

import httpx

from ...config.config import Config
from .base import BaseAnalyzer, SecurityFinding
from ...config.constants import CONSTANTS
from ...threats.threats import API_THREAT_MAPPING


enabled_rules = [
    {"rule_name": "Prompt Injection"},
    {"rule_name": "Harassment"},
    {"rule_name": "Hate Speech"},
    {"rule_name": "Profanity"},
    {"rule_name": "Sexual Content & Exploitation"},
    {"rule_name": "Social Division & Polarization"},
    {"rule_name": "Violence & Public Safety Threats"},
    {"rule_name": "Code Detection"},
]


class ApiAnalyzer(BaseAnalyzer):
    """Analyzer class for analyzing MCP tools using Cisco AI Defense API.

    This class provides functionality to analyze MCP tool descriptions for malicious content
    using the Cisco AI Defense API and returns security findings directly.

    Example:
        >>> from mcpscanner import Config
        >>> from mcpscanner.analyzers import ApiAnalyzer
        >>> config = Config(api_key="your_api_key", endpoint_url="https://eu.api.inspect.aidefense.security.cisco.com/api/v1")
        >>> analyzer = ApiAnalyzer(config)
        >>> findings = await analyzer.analyze("Tool description to analyze")
        >>> if not findings:
        ...     pass  # Tool is safe
        ... else:
        ...     pass  # Found security findings
    """

    # API endpoint for the chat inspection API
    _INSPECT_ENDPOINT = CONSTANTS.API_ENDPOINT_INSPECT_CHAT

    # Default timeout for API requests in seconds
    _DEFAULT_TIMEOUT = CONSTANTS.DEFAULT_HTTP_TIMEOUT

    def __init__(self, config: Config):
        """Initialize a new ApiAnalyzer instance.

        Args:
            config (Config): The configuration for the analyzer.
        """
        super().__init__("ApiAnalyzer")
        self._config = config

    def _get_headers(self) -> Dict[str, str]:
        """Get the headers for the API request.

        Returns:
            Dict[str, str]: The headers for the API request.
        """
        return {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-Cisco-AI-Defense-API-Key": self._config.api_key,
        }

    def _get_payload(self, content: str, include_rules: bool = True) -> Dict[str, Any]:
        """Get the payload for the API request.

        Args:
            content (str): The content to analyze.
            include_rules (bool): Whether to include enabled_rules in the config.
                Set to False if the API key has pre-configured rules.

        Returns:
            Dict[str, Any]: The payload for the API request.
        """
        payload = {
            "messages": [{"role": "user", "content": content}],
        }
        if include_rules:
            payload["config"] = {"enabled_rules": enabled_rules}
        return payload

    async def analyze(
        self, content: str, context: Optional[Dict[str, Any]] = None
    ) -> List[SecurityFinding]:
        """Analyze the provided content for malicious intent and return security findings.

        Args:
            content (str): The content to analyze.
            context (Optional[Dict[str, Any]]): Additional context for the analysis.
                Can include 'tool_name' for better logging.

        Returns:
            List[SecurityFinding]: The security findings found during the analysis.

        Raises:
            httpx.HTTPError: If the API request fails.
        """
        findings = []
        tool_name = context.get("tool_name", "unknown") if context else "unknown"

        if not content or not content.strip():
            self.logger.warning("Empty or None content provided for analysis")
            return findings

        api_url = self._config.get_api_url(self._INSPECT_ENDPOINT)
        headers = self._get_headers()
        
        # Try with rules first, then without if API key has pre-configured rules
        include_rules = True
        try:
            async with httpx.AsyncClient() as client:
                payload = self._get_payload(content, include_rules=include_rules)
                response = await client.post(
                    api_url,
                    headers=headers,
                    json=payload,
                    timeout=self._DEFAULT_TIMEOUT,
                )
                
                # Check for pre-configured rules error and retry without rules
                if response.status_code == 400:
                    try:
                        error_json = response.json()
                        error_msg = error_json.get("message", "")
                        if "already has rules configured" in error_msg:
                            self.logger.debug("API key has pre-configured rules, retrying without enabled_rules")
                            payload = self._get_payload(content, include_rules=False)
                            response = await client.post(
                                api_url,
                                headers=headers,
                                json=payload,
                                timeout=self._DEFAULT_TIMEOUT,
                            )
                    except Exception:
                        pass  # If we can't parse the error, let the original error propagate

            response.raise_for_status()
            response_json = response.json()
            is_safe = response_json.get("is_safe", True)
            classifications = response_json.get("classifications", [])

            if not is_safe:
                self.logger.debug(
                    f'Cisco AI Defense API detected malicious content: tool="{tool_name}" classifications="{classifications}"'
                )

                # Generate threat summary for all findings
                if len(classifications) == 1:
                    threat_summary = f"Detected 1 threat: {classifications[0].lower().replace('_', ' ')}"
                else:
                    threat_summary = f"Detected {len(classifications)} threats: {', '.join([c.lower().replace('_', ' ') for c in classifications])}"

                for classification in classifications:
                    # Use centralized threat mapping (includes severity)
                    threat_info = API_THREAT_MAPPING.get(classification)
                    
                    if threat_info:
                        # Severity already included in threat_info mapping
                        mapping = {
                            "severity": threat_info["severity"],
                            "category": threat_info["threat_category"],
                        }
                    else:
                        mapping = {"severity": "UNKNOWN", "category": "N/A"}

                    findings.append(
                        SecurityFinding(
                            severity=mapping["severity"],
                            summary=threat_summary,
                            analyzer="API",
                            threat_category=mapping["category"],
                            details={
                                "tool_name": tool_name,
                                "threat_type": classification,  # Store original classification for taxonomy lookup
                                "evidence": f"{classification} detected in tool content",
                                "raw_response": response_json,
                                "content_type": "text",
                            },
                        )
                    )

        except httpx.HTTPError as e:
            self.logger.error(f"API analysis failed for tool '{tool_name}': {e}")
            raise

        return findings

