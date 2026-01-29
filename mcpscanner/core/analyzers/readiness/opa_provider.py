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

"""
OPA Provider - Policy-based checks using Open Policy Agent.

Evaluates MCP tool definitions against Rego policies. The provider creates
a normalized "facts" JSON document and runs OPA against it with policies
from the data/readiness_policies/ directory.

This provider is optional. If the OPA binary is not available in PATH,
the provider will be disabled and heuristic checks will be used instead.
"""

import asyncio
import json
import shutil
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from ....utils.logging_config import get_logger

# Default policies directory (relative to mcpscanner package root)
DEFAULT_POLICIES_DIR = Path(__file__).parent.parent.parent.parent / "data" / "readiness_policies"

# Mapping from policy violation types to readiness threat categories
POLICY_CATEGORY_MAP: Dict[str, str] = {
    "timeout": "MISSING_TIMEOUT_GUARD",
    "retry": "UNSAFE_RETRY_LOOP",
    "error": "MISSING_ERROR_SCHEMA",
    "capabilities": "OVERLOADED_TOOL_SCOPE",
    "description": "SILENT_FAILURE_PATH",
    "fallback": "NO_FALLBACK_CONTRACT",
    "observability": "NO_OBSERVABILITY_HOOKS",
    "deterministic": "NON_DETERMINISTIC_RESPONSE",
}


class OpaProvider:
    """
    Open Policy Agent-based provider for readiness checks.

    Creates a "facts" JSON document from tool definitions and evaluates
    Rego policies against it. Policies are loaded from
    data/readiness_policies/*.rego files.

    This provider is optional. If OPA is not installed, it will silently
    skip policy evaluation and return an empty list of findings.

    Example facts document:
    {
        "type": "tool",
        "tool_name": "my_tool",
        "has_timeout": false,
        "timeout_value": null,
        "has_error_schema": false,
        "capabilities_count": 5,
        "has_retry_limit": true,
        "retry_limit": 3,
        ...
    }
    """

    def __init__(
        self,
        policies_dir: Optional[Path] = None,
        opa_binary: str = "opa",
    ) -> None:
        """
        Initialize the OPA provider.

        Args:
            policies_dir: Directory containing Rego policy files.
                         Defaults to mcpscanner/data/readiness_policies/
            opa_binary: Path or name of the OPA binary.
        """
        self.policies_dir = policies_dir or DEFAULT_POLICIES_DIR
        self.opa_binary = opa_binary
        self._opa_path: Optional[str] = None
        self._availability_checked = False
        self.logger = get_logger(f"{__name__}.OpaProvider")

    @property
    def name(self) -> str:
        """Return the name of this provider."""
        return "opa"

    def is_available(self) -> bool:
        """
        Check if OPA binary is available in PATH.

        Returns:
            True if OPA is available, False otherwise.
        """
        if not self._availability_checked:
            self._opa_path = shutil.which(self.opa_binary)
            self._availability_checked = True
            if self._opa_path:
                self.logger.debug(f"OPA binary found at: {self._opa_path}")
            else:
                self.logger.debug(
                    f"OPA binary '{self.opa_binary}' not found in PATH. "
                    "OPA policy checks will be skipped."
                )
        return self._opa_path is not None

    def get_unavailable_reason(self) -> Optional[str]:
        """
        Get a human-readable reason why OPA is not available.

        Returns:
            Reason string if OPA is not available, None otherwise.
        """
        if not self.is_available():
            return (
                f"OPA binary '{self.opa_binary}' not found in PATH. "
                "Install OPA: https://www.openpolicyagent.org/docs/latest/#running-opa"
            )
        return None

    async def evaluate_tool(
        self, tool_definition: Dict[str, Any], tool_name: str
    ) -> List[Dict[str, Any]]:
        """
        Evaluate a tool definition using OPA policies.

        Creates a facts document from the tool definition and evaluates
        all policies against it.

        Args:
            tool_definition: The tool definition dictionary.
            tool_name: The name of the tool being evaluated.

        Returns:
            List of violation dictionaries with keys:
            - message: The violation message
            - policy: The policy file name
            - category: The threat category
            - severity: The severity level
        """
        if not self.is_available():
            return []

        # Create facts document
        facts = self._create_tool_facts(tool_definition, tool_name)

        # Run OPA evaluation
        raw_violations = await self._evaluate_policies(facts)

        # Enrich violations with category and severity
        violations = []
        for violation in raw_violations:
            enriched = self._enrich_violation(violation)
            violations.append(enriched)

        return violations

    def _create_tool_facts(
        self, tool_definition: Dict[str, Any], tool_name: str
    ) -> Dict[str, Any]:
        """
        Create a normalized facts document from a tool definition.

        The facts document extracts key information in a consistent
        format that policies can easily evaluate.

        Args:
            tool_definition: The tool definition dictionary.
            tool_name: The name of the tool.

        Returns:
            Facts dictionary for OPA evaluation.
        """
        # Check for timeout fields
        timeout_fields = ["timeout", "timeoutMs", "timeout_ms", "timeoutSeconds"]
        timeout_value = None
        has_timeout = False
        for field in timeout_fields:
            if field in tool_definition:
                has_timeout = True
                timeout_value = tool_definition[field]
                break
            config = tool_definition.get("config", {})
            if isinstance(config, dict) and field in config:
                has_timeout = True
                timeout_value = config[field]
                break

        # Check for retry fields
        retry_fields = ["retries", "maxRetries", "max_retries", "retryLimit", "retry_limit"]
        retry_value = None
        has_retry_limit = False
        for field in retry_fields:
            if field in tool_definition:
                has_retry_limit = True
                retry_value = tool_definition[field]
                break
            config = tool_definition.get("config", {})
            if isinstance(config, dict) and field in config:
                has_retry_limit = True
                retry_value = config[field]
                break

        # Check for capabilities
        capabilities = tool_definition.get("capabilities", [])
        capabilities_count = len(capabilities) if isinstance(capabilities, list) else 0

        # Check for error schema
        error_schema_fields = ["errorSchema", "error_schema", "errors", "errorResponse"]
        has_error_schema = any(f in tool_definition for f in error_schema_fields)

        # Check for input schema
        input_schema = tool_definition.get("inputSchema", {})
        has_input_schema = bool(input_schema) and isinstance(input_schema, dict)
        input_properties_count = len(input_schema.get("properties", {})) if has_input_schema else 0
        has_required_fields = "required" in input_schema if has_input_schema else False

        # Check for description
        description = tool_definition.get("description", "")
        has_description = bool(description)
        description_length = len(description) if description else 0

        # Check for rate limiting
        rate_limit_fields = ["rateLimit", "rate_limit", "throttle", "rateLimitPerMinute"]
        has_rate_limit = any(f in tool_definition for f in rate_limit_fields)

        return {
            "type": "tool",
            "tool_name": tool_name,
            "has_timeout": has_timeout,
            "timeout_value": timeout_value,
            "has_retry_limit": has_retry_limit,
            "retry_limit": retry_value,
            "capabilities_count": capabilities_count,
            "has_error_schema": has_error_schema,
            "has_input_schema": has_input_schema,
            "input_properties_count": input_properties_count,
            "has_required_fields": has_required_fields,
            "has_description": has_description,
            "description_length": description_length,
            "has_rate_limit": has_rate_limit,
            # Include raw definition for advanced policies
            "raw": tool_definition,
        }

    async def _evaluate_policies(self, facts: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Evaluate all Rego policies against the facts document.

        Args:
            facts: The facts document to evaluate.

        Returns:
            List of raw violation dictionaries.
        """
        if not self.policies_dir.exists():
            self.logger.debug(f"Policies directory not found: {self.policies_dir}")
            return []

        violations: List[Dict[str, Any]] = []

        # Find all policy files
        policy_files = list(self.policies_dir.glob("*.rego"))
        if not policy_files:
            self.logger.debug(f"No .rego files found in: {self.policies_dir}")
            return []

        # Create temporary file for input
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as input_file:
            json.dump(facts, input_file)
            input_path = input_file.name

        try:
            # Run OPA for each policy file
            for policy_file in policy_files:
                policy_violations = await self._run_opa(policy_file, input_path)
                violations.extend(policy_violations)
        finally:
            # Clean up temp file
            Path(input_path).unlink(missing_ok=True)

        return violations

    async def _run_opa(
        self, policy_path: Path, input_path: str
    ) -> List[Dict[str, Any]]:
        """
        Run OPA evaluation for a single policy file.

        Args:
            policy_path: Path to the Rego policy file.
            input_path: Path to the JSON input file.

        Returns:
            List of violations from the policy.
        """
        violations: List[Dict[str, Any]] = []

        try:
            # Run OPA eval command
            cmd = [
                self._opa_path or "opa",
                "eval",
                "--input",
                input_path,
                "--data",
                str(policy_path),
                "--format",
                "json",
                "data.mcp.readiness.violation",
            ]

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=30.0
            )

            if process.returncode == 0:
                result = json.loads(stdout.decode("utf-8"))

                # Extract violations from OPA result
                if "result" in result and result["result"]:
                    expressions = result["result"]
                    for expr in expressions:
                        value = expr.get("value", [])
                        if isinstance(value, list):
                            for msg in value:
                                violations.append({
                                    "message": msg if isinstance(msg, str) else str(msg),
                                    "policy": policy_path.stem,
                                })
                        elif isinstance(value, str):
                            violations.append({
                                "message": value,
                                "policy": policy_path.stem,
                            })
            else:
                stderr_text = stderr.decode("utf-8") if stderr else ""
                self.logger.debug(
                    f"OPA returned non-zero exit code for {policy_path.name}: {stderr_text}"
                )

        except asyncio.TimeoutError:
            self.logger.warning(f"OPA evaluation timed out for {policy_path.name}")
            violations.append({
                "message": f"OPA evaluation timed out for {policy_path.name}",
                "policy": policy_path.stem,
                "is_error": True,
            })
        except json.JSONDecodeError as e:
            self.logger.warning(f"Failed to parse OPA output: {e}")
        except Exception as e:
            self.logger.debug(f"OPA evaluation failed: {e}")

        return violations

    def _enrich_violation(self, violation: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich a raw violation with category and severity.

        Args:
            violation: The raw violation dictionary.

        Returns:
            Enriched violation with category and severity.
        """
        message = violation.get("message", "Policy violation")
        policy = violation.get("policy", "unknown")
        is_error = violation.get("is_error", False)

        # Determine category from policy name
        category = "SILENT_FAILURE_PATH"  # Default
        for key, cat in POLICY_CATEGORY_MAP.items():
            if key in policy.lower():
                category = cat
                break

        # Errors get INFO severity, violations get MEDIUM by default
        severity = "INFO" if is_error else "MEDIUM"

        # Adjust severity based on message content
        msg_lower = message.lower()
        if "must" in msg_lower or "required" in msg_lower:
            severity = "HIGH"
        elif "should" in msg_lower or "recommended" in msg_lower:
            severity = "MEDIUM"
        elif "may" in msg_lower or "consider" in msg_lower:
            severity = "LOW"

        return {
            "message": message,
            "policy": policy,
            "category": category,
            "severity": severity,
            "rule_id": f"OPA-{policy}",
        }

