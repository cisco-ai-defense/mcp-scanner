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

This module contains the API analyzer class for analyzing MCP tools and resources using Cisco AI Defense API.
"""

from typing import Any, Dict, List, Optional

import httpx

from ...config.config import Config
from .base import BaseAnalyzer, SecurityFinding
from ...config.constants import CONSTANTS
from ...threats.threats import API_THREAT_MAPPING




class ApiAnalyzer(BaseAnalyzer):
    """Analyzer class for analyzing MCP tools and resources using Cisco AI Defense API.

    This class provides functionality to analyze MCP tool descriptions and resource content
    for malicious content using the Cisco AI Defense API and returns security findings directly.

    Example:
        >>> from mcpscanner import Config
        >>> from mcpscanner.analyzers import ApiAnalyzer
        >>> config = Config(api_key="your_api_key", endpoint_url="https://eu.api.inspect.aidefense.security.cisco.com/api/v1")
        >>> analyzer = ApiAnalyzer(config)
        >>> # Analyze a tool
        >>> findings = await analyzer.analyze("Tool description to analyze")
        >>> # Analyze a resource
        >>> findings = await analyzer.analyze("Resource content", context={"resource_uri": "file:///path/to/file"})
        >>> if not findings:
        ...     pass  # Content is safe
        ... else:
        ...     pass  # Found security findings
    """

    # API endpoint for the MCP inspection API
    _INSPECT_ENDPOINT = CONSTANTS.API_ENDPOINT_INSPECT_MCP
    _BASE_URL = CONSTANTS.API_BASE_URL_MCP

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

    def _get_payload(
        self,
        content: str,
        request_id: int = 1,
        mcp_method: str = "tools/call",
        resource_uri: Optional[str] = None,
        tool_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Get the payload for the MCP Inspection API request.

        Args:
            content (str): The content to analyze.
            request_id (int): The JSON-RPC request ID.
            mcp_method (str): The MCP method type ("tools/call" or "resources/read").
            resource_uri (Optional[str]): The URI for resource inspection.
            tool_name (Optional[str]): The tool name for tool inspection.

        Returns:
            Dict[str, Any]: The JSON-RPC 2.0 payload for the API request.
        """
        if mcp_method == "resources/read":
            return {
                "jsonrpc": "2.0",
                "method": "resources/read",
                "params": {
                    "uri": resource_uri or "unknown",
                    "content": content
                }
            }
        else:
            return {
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {
                    "name": tool_name or "analyze_content",
                    "arguments": {
                        "content": content
                    }
                }
            }

    async def analyze(
        self, content: str, context: Optional[Dict[str, Any]] = None
    ) -> List[SecurityFinding]:
        """Analyze the provided content for malicious intent and return security findings.

        Args:
            content (str): The content to analyze.
            context (Optional[Dict[str, Any]]): Additional context for the analysis.
                Can include:
                - 'tool_name': Name of the tool being analyzed
                - 'resource_uri': URI of the resource being analyzed (triggers resources/read method)
                - 'resource_name': Name of the resource for logging

        Returns:
            List[SecurityFinding]: The security findings found during the analysis.

        Raises:
            httpx.HTTPError: If the API request fails.
        """
        findings = []
        tool_name = context.get("tool_name", "unknown") if context else "unknown"
        resource_uri = context.get("resource_uri") if context else None
        resource_name = context.get("resource_name", "unknown") if context else "unknown"

        # Determine if this is a resource or tool analysis
        is_resource = resource_uri is not None
        item_name = resource_name if is_resource else tool_name
        mcp_method = "resources/read" if is_resource else "tools/call"

        if not content or not content.strip():
            self.logger.warning("Empty or None content provided for analysis")
            return findings

        api_url = f"{self._BASE_URL}/{self._INSPECT_ENDPOINT}"
        headers = self._get_headers()

        try:
            async with httpx.AsyncClient() as client:
                payload = self._get_payload(
                    content,
                    mcp_method=mcp_method,
                    resource_uri=resource_uri,
                    tool_name=tool_name if not is_resource else None,
                )
                response = await client.post(
                    api_url,
                    headers=headers,
                    json=payload,
                    timeout=self._DEFAULT_TIMEOUT,
                )

            response.raise_for_status()
            response_json = response.json()

            # Handle JSON-RPC 2.0 error response
            if "error" in response_json:
                error = response_json.get("error", {})
                self.logger.error(
                    f"MCP Inspection API error: code={error.get('code')}, message={error.get('message')}"
                )
                return findings

            # Extract result from JSON-RPC 2.0 response
            result = response_json.get("result", {})
            is_safe = result.get("is_safe", True)
            classifications = result.get("classifications", [])
            severity = result.get("severity", "NONE_SEVERITY")
            action = result.get("action", "Allow")
            explanation = result.get("explanation", "")
            rules = result.get("rules", [])

            if not is_safe:
                self.logger.debug(
                    f'MCP Inspection API detected malicious content: {"resource" if is_resource else "tool"}="{item_name}" classifications="{classifications}" action="{action}"'
                )

                # Use explanation from API if available, otherwise generate summary
                if explanation:
                    threat_summary = explanation
                elif len(classifications) == 1:
                    threat_summary = f"Detected 1 threat: {classifications[0].lower().replace('_', ' ')}"
                else:
                    threat_summary = f"Detected {len(classifications)} threats: {', '.join([c.lower().replace('_', ' ') for c in classifications])}"

                # Map API severity to internal severity
                severity_mapping = {
                    "CRITICAL": "HIGH",
                    "HIGH": "HIGH",
                    "MEDIUM": "MEDIUM",
                    "LOW": "LOW",
                    "NONE_SEVERITY": "LOW",
                }

                for classification in classifications:
                    # Use centralized threat mapping for category
                    threat_info = API_THREAT_MAPPING.get(classification)

                    if threat_info:
                        category = threat_info["threat_category"]
                    else:
                        category = "N/A"

                    # Prefer API-provided severity, fallback to threat mapping
                    api_severity = severity_mapping.get(severity, None)
                    if api_severity:
                        finding_severity = api_severity
                    elif threat_info:
                        finding_severity = threat_info["severity"]
                    else:
                        finding_severity = "UNKNOWN"

                    details = {
                        "threat_type": classification,
                        "evidence": f"{classification} detected in {'resource' if is_resource else 'tool'} content",
                        "action": action,
                        "attack_technique": result.get("attack_technique", ""),
                        "rules": rules,
                        "event_id": result.get("event_id", ""),
                        "client_transaction_id": result.get("client_transaction_id", ""),
                        "raw_response": response_json,
                        "content_type": "text",
                    }

                    if is_resource:
                        details["resource_name"] = resource_name
                        details["resource_uri"] = resource_uri
                    else:
                        details["tool_name"] = tool_name

                    findings.append(
                        SecurityFinding(
                            severity=finding_severity,
                            summary=threat_summary,
                            analyzer="API",
                            threat_category=category,
                            details=details,
                        )
                    )

        except httpx.HTTPError as e:
            self.logger.error(f"API analysis failed for {'resource' if is_resource else 'tool'} '{item_name}': {e}")
            raise

        return findings
