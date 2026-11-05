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
Readiness Analyzer for MCP Scanner SDK.

Analyzes MCP tools for production readiness issues using zero-dependency
heuristic checks and optional OPA policy evaluation.

This analyzer focuses on operational reliability, NOT security vulnerabilities.
It detects issues like missing timeouts, unsafe retry loops, and silent failures.

Implements 20 core heuristic rules (HEUR-001 through HEUR-020):

Timeout Guards (HEUR-001, HEUR-002):
- Missing timeout configuration
- Timeout values too long (>5 minutes)

Retry Configuration (HEUR-003, HEUR-004, HEUR-005):
- No retry limit defined
- Unlimited or excessive retries
- Missing backoff strategy

Error Handling (HEUR-006, HEUR-007, HEUR-008):
- Missing error schema
- Error schema without error code field
- Missing output schema

Description Quality (HEUR-009, HEUR-010):
- Vague or missing descriptions
- Overloaded tool scope indicators

Input Validation (HEUR-011, HEUR-012):
- No required fields defined
- Missing input validation hints

Operational Config (HEUR-013, HEUR-014, HEUR-015):
- No rate limiting
- Missing version information
- No observability configuration

Resource Management (HEUR-016, HEUR-017):
- Resource cleanup not documented
- No idempotency indication

Safety (HEUR-018, HEUR-019, HEUR-020):
- Dangerous operation keywords
- No authentication context
- Circular dependency risk

Optional OPA Integration:
- If OPA is installed and available in PATH, additional policy-based checks
  are performed using Rego policies from data/readiness_policies/
- OPA findings are merged with heuristic findings
- If OPA is not available, only heuristic checks are performed

Optional LLM-based Semantic Analysis:
- When MCP_SCANNER_LLM_API_KEY is set and enable_llm_judge=True, additional
  semantic checks are performed using LLM to evaluate aspects that heuristics
  cannot detect:
  - Actionable error handling
  - Failure mode documentation quality
  - Scope clarity assessment
- LLM judge is disabled by default and requires explicit opt-in
"""

import json
from typing import Any, Dict, List, Optional

from ....utils.analyzer_errors import build_infrastructure_error_finding
from ..base import BaseAnalyzer, SecurityFinding
from .opa_provider import OpaProvider


class ReadinessCheckFailure(Exception):
    """At least one local readiness check failed.

    ``findings`` are the results of the checks that finished.
    ``failed_checks`` are rule ids such as ``HEUR-018``. The message stays
    generic so tool text is not copied into logs.
    """

    def __init__(self, findings: List[SecurityFinding], failed_checks: List[str]):
        super().__init__("readiness check failed")
        self.findings = findings
        self.failed_checks = self.safe_rule_ids(failed_checks)

    @staticmethod
    def safe_rule_ids(rule_ids: Any) -> List[str]:
        """Keep rule ids. Drop anything that is not a ``HEUR-`` number."""
        if not isinstance(rule_ids, (list, tuple)):
            return []
        safe = []
        for rule_id in rule_ids:
            if (
                isinstance(rule_id, str)
                and rule_id.startswith("HEUR-")
                and rule_id[5:].isdigit()
            ):
                safe.append(rule_id)
        return safe


class ReadinessAnalyzer(BaseAnalyzer):
    """
    Analyzer for production readiness issues in MCP tools.

    This analyzer requires NO external dependencies or API keys for core
    functionality. It performs static analysis of tool definitions using
    heuristics to detect operational issues that may cause reliability
    problems in production.

    Optionally, if OPA (Open Policy Agent) is installed, additional
    policy-based checks are performed. OPA is not required - if not
    available, the analyzer falls back to heuristic-only mode.

    Example:
        >>> from mcpscanner.core.analyzers import ReadinessAnalyzer
        >>> analyzer = ReadinessAnalyzer()
        >>> findings = await analyzer.analyze(tool_json_content)
        >>> for finding in findings:
        ...     print(f"{finding.severity}: {finding.summary}")

    Example with OPA enabled:
        >>> analyzer = ReadinessAnalyzer(enable_opa=True)
        >>> # If OPA is in PATH, policy checks will also run
        >>> findings = await analyzer.analyze(tool_json_content)

    Example with LLM semantic analysis:
        >>> import os
        >>> os.environ["MCP_SCANNER_LLM_API_KEY"] = "your-api-key"
        >>> analyzer = ReadinessAnalyzer(enable_llm_judge=True)
        >>> findings = await analyzer.analyze(tool_json_content)
    """

    # Highest severity each local check can report. A skipped check is
    # surfaced at this severity so a high-only report still shows it.
    CHECK_SEVERITY = {
        "HEUR-001": "HIGH",
        "HEUR-002": "MEDIUM",
        "HEUR-003": "MEDIUM",
        "HEUR-004": "HIGH",
        "HEUR-005": "LOW",
        "HEUR-006": "MEDIUM",
        "HEUR-007": "LOW",
        "HEUR-008": "LOW",
        "HEUR-009": "MEDIUM",
        "HEUR-010": "HIGH",
        "HEUR-011": "LOW",
        "HEUR-012": "INFO",
        "HEUR-013": "LOW",
        "HEUR-014": "LOW",
        "HEUR-015": "LOW",
        "HEUR-016": "MEDIUM",
        "HEUR-017": "INFO",
        "HEUR-018": "HIGH",
        "HEUR-019": "INFO",
        "HEUR-020": "MEDIUM",
    }
    SEVERITY_RANK = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")

    # Severity deductions for readiness score calculation
    SEVERITY_DEDUCTIONS = {
        "CRITICAL": 25,
        "HIGH": 15,
        "MEDIUM": 8,
        "LOW": 3,
        "INFO": 1,
    }

    def __init__(
        self,
        config=None,
        max_capabilities: int = 10,
        min_description_length: int = 20,
        enable_opa: bool = False,
        opa_policies_dir: Optional[str] = None,
        enable_llm_judge: bool = False,
        llm_model: Optional[str] = None,
        llm_api_key: Optional[str] = None,
    ):
        """Initialize the ReadinessAnalyzer.

        Args:
            config: Optional configuration object (unused, for interface consistency).
            max_capabilities: Maximum capabilities before flagging overload.
            min_description_length: Minimum description length before warning.
            enable_opa: Whether to enable OPA policy checks (default: False).
                       If True and OPA is not available, a debug message is logged
                       and heuristic-only mode is used.
            opa_policies_dir: Optional path to custom Rego policies directory.
                             If not specified, uses built-in policies.
            enable_llm_judge: Whether to enable LLM-based semantic analysis
                             (default: False). Requires MCP_SCANNER_LLM_API_KEY
                             environment variable to be set.
            llm_model: Override LLM model for semantic analysis.
            llm_api_key: Override LLM API key for semantic analysis.
        """
        super().__init__("READINESS")
        self.max_capabilities = max_capabilities
        self.min_description_length = min_description_length
        self.enable_opa = enable_opa
        self._enable_llm_judge = enable_llm_judge

        # Initialize OPA provider if enabled
        self._opa_provider: Optional[OpaProvider] = None
        if enable_opa:
            from pathlib import Path
            policies_dir = Path(opa_policies_dir) if opa_policies_dir else None
            self._opa_provider = OpaProvider(policies_dir=policies_dir)

            if self._opa_provider.is_available():
                self.logger.info("OPA provider enabled and available")
            else:
                reason = self._opa_provider.get_unavailable_reason()
                self.logger.debug(f"OPA not available: {reason}")

        # Initialize LLM judge if enabled
        self._llm_judge = None
        if enable_llm_judge:
            self._init_llm_judge(llm_model, llm_api_key)

    def _init_llm_judge(
        self,
        llm_model: Optional[str] = None,
        llm_api_key: Optional[str] = None,
    ) -> None:
        """Initialize the LLM judge for semantic analysis."""
        try:
            from .llm_judge import ReadinessLLMJudge

            self._llm_judge = ReadinessLLMJudge(
                model=llm_model,
                api_key=llm_api_key,
            )
            if self._llm_judge.is_available():
                self.logger.info("Readiness LLM judge enabled and available")
            else:
                reason = self._llm_judge.get_unavailable_reason()
                self.logger.debug(f"LLM judge not available: {reason}")
        except ImportError as e:
            self.logger.debug(f"Could not initialize LLM judge: {e}")
            self._llm_judge = None

    @property
    def llm_judge_available(self) -> bool:
        """Check if LLM judge is available for semantic analysis."""
        return self._llm_judge is not None and self._llm_judge.is_available()

    def _tool_context(
        self, content: str, context: Optional[Dict[str, Any]]
    ) -> tuple:
        """Return ``(tool_name, tool_def)`` for a readiness scan."""
        tool_name = context.get("tool_name", "unknown") if context else "unknown"
        tool_def = self._parse_tool_definition(content, context)
        return tool_name, tool_def

    @staticmethod
    def _text(value: Any) -> str:
        """Return ``value`` when it is text, otherwise an empty string."""
        return value if isinstance(value, str) else ""

    @staticmethod
    def _number(value: Any) -> Optional[float]:
        """Return a real number, ignoring booleans and other types."""
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return None
        return float(value)

    @staticmethod
    def _mapping(value: Any) -> Dict[str, Any]:
        """Return ``value`` when it is a dict, otherwise an empty dict."""
        return value if isinstance(value, dict) else {}

    def _description(self, tool_def: Dict[str, Any]) -> str:
        """Tool description text. A null description is an empty string."""
        return self._text(tool_def.get("description"))

    @property
    def opa_enabled(self) -> bool:
        """True when OPA policy checks can run."""
        return self._opa_provider is not None and self._opa_provider.is_available()

    def heuristic_findings(
        self, content: str, context: Optional[Dict[str, Any]] = None
    ) -> List[SecurityFinding]:
        """Local readiness checks. These do not call the network."""
        tool_name, tool_def = self._tool_context(content, context)
        if not tool_def:
            return []
        findings, failed_checks = self._run_heuristic_checks(tool_def, tool_name)
        if failed_checks:
            raise ReadinessCheckFailure(findings, failed_checks)
        return findings

    async def opa_findings(
        self, content: str, context: Optional[Dict[str, Any]] = None
    ) -> List[SecurityFinding]:
        """OPA policy checks. Safe to cancel without dropping heuristics."""
        tool_name, tool_def = self._tool_context(content, context)
        if not tool_def or not self.opa_enabled:
            return []
        return await self._run_opa_checks(tool_def, tool_name)

    async def judge_findings(
        self, content: str, context: Optional[Dict[str, Any]] = None
    ) -> List[SecurityFinding]:
        """LLM-judge checks. Cancellation leaves OPA and heuristic findings."""
        tool_name, tool_def = self._tool_context(content, context)
        if not tool_def or not self.llm_judge_available:
            return []
        try:
            return await self._llm_judge.analyze(tool_def, tool_name)
        except Exception as e:
            self.logger.warning("LLM judge analysis failed: %s", type(e).__name__)
            raise

    async def remote_findings(
        self, content: str, context: Optional[Dict[str, Any]] = None
    ) -> List[SecurityFinding]:
        """OPA and LLM-judge checks for callers that run them together.

        A failed judge stays on the result as an infrastructure finding.
        OPA findings already collected are kept.
        """
        tool_name, _tool_def = self._tool_context(content, context)
        findings = await self.opa_findings(content, context)
        try:
            findings.extend(await self.judge_findings(content, context))
        except Exception as exc:
            findings.append(
                build_infrastructure_error_finding(
                    analyzer_name="READINESS",
                    subject=tool_name or "unknown",
                    error=exc,
                )
            )
        return findings

    def incomplete_check_finding(
        self, tool_name: str, failed_checks: Optional[List[str]] = None
    ) -> SecurityFinding:
        """A finding that names the local checks that did not finish.

        Rule ids are included. The check's exception text is not.
        """
        label = self._text(tool_name) or "unknown"
        rules = ReadinessCheckFailure.safe_rule_ids(failed_checks or [])
        named = ", ".join(rules) if rules else "an unnamed check"
        return self.create_security_finding(
            severity=self._severity_for_gap(rules),
            summary=(
                f"Tool '{label}' did not finish readiness checks {named}. "
                "No readiness score is reported for this tool."
            ),
            threat_category="SILENT_FAILURE_PATH",
            details={
                "tool_name": label,
                "rule_id": "HEUR-INCOMPLETE",
                "failed_checks": rules,
                "checks_completed": False,
            },
        )

    def mark_checks_incomplete(
        self,
        findings: List[SecurityFinding],
        failed_checks: Optional[List[str]] = None,
    ) -> List[SecurityFinding]:
        """Drop the score when a check did not run."""
        rules = ReadinessCheckFailure.safe_rule_ids(failed_checks or [])
        for finding in findings:
            if finding.details is None:
                finding.details = {}
            finding.details["checks_completed"] = False
            finding.details["is_production_ready"] = False
            finding.details["readiness_score"] = None
            finding.details["failed_checks"] = rules
        return findings

    def _severity_for_gap(self, rules: List[str]) -> str:
        """Use the highest severity among the checks that did not run."""
        if not rules:
            return "HIGH"
        rank = {name: index for index, name in enumerate(self.SEVERITY_RANK)}
        chosen = "INFO"
        for rule_id in rules:
            severity = self.CHECK_SEVERITY.get(rule_id, "HIGH")
            if rank.get(severity, 0) >= rank.get(chosen, 0):
                chosen = severity
        return chosen

    def stamp_readiness(
        self, findings: List[SecurityFinding]
    ) -> List[SecurityFinding]:
        """Attach the readiness score to each finding."""
        score = self._calculate_readiness_score(findings)
        is_production_ready = score >= 70 and not any(
            f.severity == "CRITICAL" for f in findings
        )
        for finding in findings:
            if finding.details is None:
                finding.details = {}
            finding.details["readiness_score"] = score
            finding.details["is_production_ready"] = is_production_ready
        return findings

    async def analyze(
        self, content: str, context: Optional[Dict[str, Any]] = None
    ) -> List[SecurityFinding]:
        """
        Analyze tool definition content for readiness issues.

        Args:
            content: JSON string of tool definition or description text.
            context: Additional context (tool_name, content_type, etc.).

        Returns:
            List of SecurityFinding objects for readiness issues.
        """
        tool_name, _tool_def = self._tool_context(content, context)
        failed_checks: List[str] = []
        try:
            findings = self.heuristic_findings(content, context)
        except ReadinessCheckFailure as exc:
            findings = list(exc.findings)
            failed_checks = list(exc.failed_checks)
            findings.append(self.incomplete_check_finding(tool_name, failed_checks))
        findings.extend(await self.remote_findings(content, context))
        stamped = self.stamp_readiness(findings)
        judge_incomplete = any(
            getattr(finding, "threat_category", None) == "ANALYZER INFRASTRUCTURE"
            for finding in stamped
        )
        if failed_checks or judge_incomplete:
            self.mark_checks_incomplete(stamped, failed_checks)
        return stamped

    def _run_heuristic_checks(
        self, tool_def: Dict[str, Any], tool_name: str
    ) -> tuple:
        """Run all heuristic checks on the tool definition.

        Returns ``(findings, failed_checks)``. A check that raises is
        skipped. Findings from the checks that finished are still
        returned, with the rule ids of the checks that did not.
        """
        findings: List[SecurityFinding] = []
        failed_checks: List[str] = []
        checks = (
            ("HEUR-001", self._check_missing_timeout),
            ("HEUR-002", self._check_timeout_too_long),
            ("HEUR-003", self._check_no_retry_limit),
            ("HEUR-004", self._check_unlimited_retries),
            ("HEUR-005", self._check_no_backoff_strategy),
            ("HEUR-006", self._check_missing_error_schema),
            ("HEUR-007", self._check_error_schema_missing_code),
            ("HEUR-008", self._check_no_output_schema),
            ("HEUR-009", self._check_vague_description),
            ("HEUR-010", self._check_too_many_capabilities),
            ("HEUR-011", self._check_no_required_fields),
            ("HEUR-012", self._check_no_input_validation_hints),
            ("HEUR-013", self._check_no_rate_limit),
            ("HEUR-014", self._check_no_version),
            ("HEUR-015", self._check_no_observability),
            ("HEUR-016", self._check_resource_cleanup_not_documented),
            ("HEUR-017", self._check_no_idempotency_indication),
            ("HEUR-018", self._check_dangerous_operation_keywords),
            ("HEUR-019", self._check_no_authentication_context),
            ("HEUR-020", self._check_circular_dependency_risk),
        )
        for rule_id, check in checks:
            try:
                findings.extend(check(tool_def, tool_name))
            except Exception as exc:
                failed_checks.append(rule_id)
                self.logger.warning(
                    "Readiness check %s failed: %s",
                    rule_id,
                    type(exc).__name__,
                )
        return findings, failed_checks

    async def _run_opa_checks(
        self, tool_def: Dict[str, Any], tool_name: str
    ) -> List[SecurityFinding]:
        """
        Run OPA policy checks on the tool definition.

        Args:
            tool_def: The tool definition dictionary.
            tool_name: The name of the tool.

        Returns:
            List of SecurityFinding objects from OPA violations.
        """
        findings: List[SecurityFinding] = []

        if not self._opa_provider:
            return findings

        violations = await self._opa_provider.evaluate_tool(tool_def, tool_name)

        for violation in violations:
            finding = self.create_security_finding(
                severity=violation.get("severity", "MEDIUM"),
                summary=violation.get("message", "Policy violation"),
                threat_category=violation.get("category", "SILENT_FAILURE_PATH"),
                details={
                    "tool_name": tool_name,
                    "rule_id": violation.get("rule_id", "OPA-unknown"),
                    "location": f"tool.{tool_name}",
                    "policy": violation.get("policy", "unknown"),
                    "source": "opa",
                },
            )
            findings.append(finding)

        return findings

    def _parse_tool_definition(
        self, content: str, context: Optional[Dict[str, Any]]
    ) -> Optional[Dict[str, Any]]:
        """Parse content as JSON tool definition."""
        # If context already has tool definition, use it
        if context and "tool_definition" in context:
            return context["tool_definition"]

        # Try to parse content as JSON
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            # Content is plain text (description), wrap it
            tool_name = context.get("tool_name", "unknown") if context else "unknown"
            return {
                "name": tool_name,
                "description": content,
            }

    def _calculate_readiness_score(self, findings: List[SecurityFinding]) -> int:
        """Calculate readiness score (0-100) based on findings."""
        score = 100
        for finding in findings:
            deduction = self.SEVERITY_DEDUCTIONS.get(finding.severity, 0)
            score -= deduction
        return max(0, score)

    # ===================================================================
    # HEUR-001: Missing timeout (HIGH)
    # ===================================================================
    def _check_missing_timeout(
        self, tool_def: Dict[str, Any], tool_name: str
    ) -> List[SecurityFinding]:
        """HEUR-001: Check for missing timeout configuration."""
        findings: List[SecurityFinding] = []

        timeout_fields = ["timeout", "timeoutMs", "timeout_ms", "timeoutSeconds"]
        has_timeout = any(field in tool_def for field in timeout_fields)

        # Also check nested config
        config = self._mapping(tool_def.get("config"))
        has_timeout = has_timeout or any(field in config for field in timeout_fields)

        if not has_timeout:
            findings.append(
                self.create_security_finding(
                    severity="HIGH",
                    summary=(
                        f"Tool '{tool_name}' does not specify a timeout. "
                        "Operations may hang indefinitely if external services "
                        "become unresponsive."
                    ),
                    threat_category="MISSING_TIMEOUT_GUARD",
                    details={
                        "tool_name": tool_name,
                        "rule_id": "HEUR-001",
                        "location": f"tool.{tool_name}",
                        "recommendation": (
                            "Add a 'timeout' or 'timeoutMs' field with a reasonable "
                            "value (e.g., 30000 for 30 seconds)"
                        ),
                    },
                )
            )

        return findings

    # ===================================================================
    # HEUR-002: Timeout too long (MEDIUM)
    # ===================================================================
    def _check_timeout_too_long(
        self, tool_def: Dict[str, Any], tool_name: str
    ) -> List[SecurityFinding]:
        """HEUR-002: Check if timeout is greater than 300000ms (5 minutes)."""
        findings: List[SecurityFinding] = []

        timeout_fields = ["timeout", "timeoutMs", "timeout_ms"]
        config = self._mapping(tool_def.get("config"))

        for field in timeout_fields:
            raw_timeout = tool_def.get(field) or config.get(field)
            timeout_value = self._number(raw_timeout)
            if timeout_value is not None and timeout_value > 300000:
                findings.append(
                    self.create_security_finding(
                        severity="MEDIUM",
                        summary=(
                            f"Tool '{tool_name}' has {field}={raw_timeout}ms "
                            "(over 5 minutes). Long timeouts can cause extended hangs "
                            "and poor user experience."
                        ),
                        threat_category="MISSING_TIMEOUT_GUARD",
                        details={
                            "tool_name": tool_name,
                            "rule_id": "HEUR-002",
                            "location": f"tool.{tool_name}.{field}",
                            "field": field,
                            "value": timeout_value,
                            "recommendation": (
                                "Consider reducing timeout to 30-60 seconds "
                                "for better responsiveness"
                            ),
                        },
                    )
                )

        return findings

    # ===================================================================
    # HEUR-003: No retry limit (MEDIUM)
    # ===================================================================
    def _check_no_retry_limit(
        self, tool_def: Dict[str, Any], tool_name: str
    ) -> List[SecurityFinding]:
        """HEUR-003: Check for missing retry limit configuration."""
        findings: List[SecurityFinding] = []

        retry_fields = [
            "maxRetries",
            "retries",
            "max_retries",
            "retryCount",
            "retryLimit",
            "retry_limit",
        ]
        has_retries = any(field in tool_def for field in retry_fields)

        config = self._mapping(tool_def.get("config"))
        has_retries = has_retries or any(field in config for field in retry_fields)

        # Also check for retryPolicy object
        retry_policy = tool_def.get("retryPolicy") or config.get("retryPolicy")
        if retry_policy and isinstance(retry_policy, dict):
            has_retries = has_retries or any(
                field in retry_policy for field in retry_fields
            )

        if not has_retries:
            findings.append(
                self.create_security_finding(
                    severity="MEDIUM",
                    summary=(
                        f"Tool '{tool_name}' does not specify a retry limit. "
                        "Without limits, retry logic may cause resource exhaustion "
                        "or infinite loops."
                    ),
                    threat_category="UNSAFE_RETRY_LOOP",
                    details={
                        "tool_name": tool_name,
                        "rule_id": "HEUR-003",
                        "location": f"tool.{tool_name}",
                        "recommendation": (
                            "Add a 'maxRetries' or 'retryLimit' field with a "
                            "reasonable value (e.g., 3)"
                        ),
                    },
                )
            )

        return findings

    # ===================================================================
    # HEUR-004: Unlimited retries (HIGH)
    # ===================================================================
    def _check_unlimited_retries(
        self, tool_def: Dict[str, Any], tool_name: str
    ) -> List[SecurityFinding]:
        """HEUR-004: Check for unlimited retries (maxRetries == -1 or > 10)."""
        findings: List[SecurityFinding] = []

        retry_fields = ["maxRetries", "retries", "max_retries", "retryLimit"]
        config = self._mapping(tool_def.get("config"))
        retry_policy = tool_def.get("retryPolicy") or config.get("retryPolicy") or {}

        for field in retry_fields:
            retry_value = (
                tool_def.get(field)
                or config.get(field)
                or (retry_policy.get(field) if isinstance(retry_policy, dict) else None)
            )

            numeric_retry = self._number(retry_value)
            if numeric_retry is not None:
                if numeric_retry == -1:
                    findings.append(
                        self.create_security_finding(
                            severity="HIGH",
                            summary=(
                                f"Tool '{tool_name}' has {field}=-1, indicating "
                                "unlimited retries. This can cause infinite loops "
                                "and resource exhaustion."
                            ),
                            threat_category="UNSAFE_RETRY_LOOP",
                            details={
                                "tool_name": tool_name,
                                "rule_id": "HEUR-004",
                                "location": f"tool.{tool_name}.{field}",
                                "field": field,
                                "value": retry_value,
                                "recommendation": (
                                    "Set a finite retry limit (recommended: 3-5 retries)"
                                ),
                            },
                        )
                    )
                elif numeric_retry > 10:
                    findings.append(
                        self.create_security_finding(
                            severity="HIGH",
                            summary=(
                                f"Tool '{tool_name}' has {field}={retry_value}. "
                                "Very high retry limits may cause extended delays "
                                "during outages."
                            ),
                            threat_category="UNSAFE_RETRY_LOOP",
                            details={
                                "tool_name": tool_name,
                                "rule_id": "HEUR-004",
                                "location": f"tool.{tool_name}.{field}",
                                "field": field,
                                "value": retry_value,
                                "recommendation": "Consider reducing retry limit to 3-5",
                            },
                        )
                    )

        return findings

    # ===================================================================
    # HEUR-005: No backoff strategy (LOW)
    # ===================================================================
    def _check_no_backoff_strategy(
        self, tool_def: Dict[str, Any], tool_name: str
    ) -> List[SecurityFinding]:
        """HEUR-005: Check for missing backoff strategy when retries are configured."""
        findings: List[SecurityFinding] = []

        # First check if retries are configured
        retry_fields = ["maxRetries", "retries", "max_retries", "retryLimit"]
        config = self._mapping(tool_def.get("config"))
        retry_policy = tool_def.get("retryPolicy") or config.get("retryPolicy") or {}

        has_retries = any(
            (
                tool_def.get(field)
                or config.get(field)
                or (retry_policy.get(field) if isinstance(retry_policy, dict) else None)
            )
            for field in retry_fields
        )

        if has_retries:
            # Check for backoff configuration
            backoff_fields = [
                "backoff",
                "backoffMs",
                "exponentialBackoff",
                "backoffStrategy",
                "retryDelay",
                "retryBackoff",
            ]
            has_backoff = any(field in tool_def for field in backoff_fields)
            has_backoff = has_backoff or any(field in config for field in backoff_fields)
            has_backoff = has_backoff or (
                isinstance(retry_policy, dict)
                and any(field in retry_policy for field in backoff_fields)
            )

            if not has_backoff:
                findings.append(
                    self.create_security_finding(
                        severity="LOW",
                        summary=(
                            f"Tool '{tool_name}' has retry logic but no backoff strategy. "
                            "Without backoff, rapid retries can overwhelm failing services."
                        ),
                        threat_category="UNSAFE_RETRY_LOOP",
                        details={
                            "tool_name": tool_name,
                            "rule_id": "HEUR-005",
                            "location": f"tool.{tool_name}",
                            "recommendation": (
                                "Add exponential backoff configuration (e.g., backoffMs, "
                                "exponentialBackoff) to avoid thundering herd problems"
                            ),
                        },
                    )
                )

        return findings

    # ===================================================================
    # HEUR-006: Missing error schema (MEDIUM)
    # ===================================================================
    def _check_missing_error_schema(
        self, tool_def: Dict[str, Any], tool_name: str
    ) -> List[SecurityFinding]:
        """HEUR-006: Check for missing error response schema."""
        findings: List[SecurityFinding] = []

        error_schema_fields = ["errorSchema", "error_schema", "errors", "errorResponse"]
        has_error_schema = any(field in tool_def for field in error_schema_fields)

        if not has_error_schema:
            findings.append(
                self.create_security_finding(
                    severity="MEDIUM",
                    summary=(
                        f"Tool '{tool_name}' does not define an error response schema. "
                        "Without structured error responses, agents cannot "
                        "programmatically handle failures."
                    ),
                    threat_category="MISSING_ERROR_SCHEMA",
                    details={
                        "tool_name": tool_name,
                        "rule_id": "HEUR-006",
                        "location": f"tool.{tool_name}",
                        "recommendation": (
                            "Add an 'errorSchema' field defining the structure of "
                            "error responses with error codes and messages"
                        ),
                    },
                )
            )

        return findings

    # ===================================================================
    # HEUR-007: Error schema missing code field (LOW)
    # ===================================================================
    def _check_error_schema_missing_code(
        self, tool_def: Dict[str, Any], tool_name: str
    ) -> List[SecurityFinding]:
        """HEUR-007: Check if error schema exists but lacks a 'code' property."""
        findings: List[SecurityFinding] = []

        error_schema_fields = ["errorSchema", "error_schema", "errors", "errorResponse"]

        for field in error_schema_fields:
            error_schema = tool_def.get(field)
            if error_schema and isinstance(error_schema, dict):
                properties = error_schema.get("properties", {})
                if "code" not in properties and "errorCode" not in properties:
                    findings.append(
                        self.create_security_finding(
                            severity="LOW",
                            summary=(
                                f"Tool '{tool_name}' has an error schema but it doesn't "
                                "include a 'code' or 'errorCode' property. Error codes are "
                                "essential for programmatic error handling."
                            ),
                            threat_category="MISSING_ERROR_SCHEMA",
                            details={
                                "tool_name": tool_name,
                                "rule_id": "HEUR-007",
                                "location": f"tool.{tool_name}.{field}.properties",
                                "recommendation": (
                                    "Add a 'code' property to the error schema "
                                    "(e.g., string enum of error codes)"
                                ),
                            },
                        )
                    )
                break  # Only check the first error schema found

        return findings

    # ===================================================================
    # HEUR-008: No output schema (LOW)
    # ===================================================================
    def _check_no_output_schema(
        self, tool_def: Dict[str, Any], tool_name: str
    ) -> List[SecurityFinding]:
        """HEUR-008: Check for missing output/response schema."""
        findings: List[SecurityFinding] = []

        output_schema_fields = [
            "outputSchema",
            "output_schema",
            "responseSchema",
            "response_schema",
        ]
        # A null or empty value is present on MCP tool dumps and is not a schema.
        has_output_schema = any(
            isinstance(tool_def.get(field), dict) and bool(tool_def.get(field))
            for field in output_schema_fields
            if field in tool_def
        )

        if not has_output_schema:
            findings.append(
                self.create_security_finding(
                    severity="LOW",
                    summary=(
                        f"Tool '{tool_name}' does not define an output schema. "
                        "Agents cannot reliably parse responses without knowing "
                        "the expected structure."
                    ),
                    threat_category="MISSING_ERROR_SCHEMA",
                    details={
                        "tool_name": tool_name,
                        "rule_id": "HEUR-008",
                        "location": f"tool.{tool_name}",
                        "recommendation": (
                            "Add an 'outputSchema' field defining the structure "
                            "of successful responses"
                        ),
                    },
                )
            )

        return findings

    # ===================================================================
    # HEUR-009: Vague description (MEDIUM)
    # ===================================================================
    def _check_vague_description(
        self, tool_def: Dict[str, Any], tool_name: str
    ) -> List[SecurityFinding]:
        """HEUR-009: Check if description is missing or too short (<20 chars)."""
        findings: List[SecurityFinding] = []

        description = self._description(tool_def)

        if not description:
            findings.append(
                self.create_security_finding(
                    severity="MEDIUM",
                    summary=(
                        f"Tool '{tool_name}' has no description. "
                        "Agents rely on descriptions to understand tool capabilities "
                        "and select the appropriate tool for tasks."
                    ),
                    threat_category="OVERLOADED_TOOL_SCOPE",
                    details={
                        "tool_name": tool_name,
                        "rule_id": "HEUR-009",
                        "location": f"tool.{tool_name}.description",
                        "recommendation": (
                            "Add a clear, detailed description explaining what the tool does"
                        ),
                    },
                )
            )
        elif len(description) < self.min_description_length:
            findings.append(
                self.create_security_finding(
                    severity="MEDIUM",
                    summary=(
                        f"Tool '{tool_name}' has a very short description "
                        f"({len(description)} characters, minimum {self.min_description_length} recommended). "
                        "Brief descriptions may not provide enough context for agents."
                    ),
                    threat_category="OVERLOADED_TOOL_SCOPE",
                    details={
                        "tool_name": tool_name,
                        "rule_id": "HEUR-009",
                        "location": f"tool.{tool_name}.description",
                        "length": len(description),
                        "minimum": self.min_description_length,
                        "recommendation": (
                            "Expand the description to explain the tool's purpose, "
                            "inputs, and expected outputs"
                        ),
                    },
                )
            )
        else:
            # Check for generic-only words
            generic_words = ["tool", "utility", "helper", "function", "method"]
            words = description.lower().split()
            non_generic_words = [w for w in words if w not in generic_words]

            if len(non_generic_words) < 3:
                findings.append(
                    self.create_security_finding(
                        severity="MEDIUM",
                        summary=(
                            f"Tool '{tool_name}' description contains only generic words. "
                            "Add specific details about what the tool does."
                        ),
                        threat_category="OVERLOADED_TOOL_SCOPE",
                        details={
                            "tool_name": tool_name,
                            "rule_id": "HEUR-009",
                            "location": f"tool.{tool_name}.description",
                            "recommendation": (
                                "Replace generic terms with specific details about functionality"
                            ),
                        },
                    )
                )

        return findings

    # ===================================================================
    # HEUR-010: Too many capabilities (HIGH)
    # ===================================================================
    def _check_too_many_capabilities(
        self, tool_def: Dict[str, Any], tool_name: str
    ) -> List[SecurityFinding]:
        """HEUR-010: Check if description mentions >5 verbs or overload keywords."""
        findings: List[SecurityFinding] = []

        description = self._description(tool_def).lower()

        # Check for overload keywords
        overload_keywords = ["any", "all", "everything", "anything", "whatever"]
        found_overload_keywords = [kw for kw in overload_keywords if kw in description]

        if found_overload_keywords:
            findings.append(
                self.create_security_finding(
                    severity="HIGH",
                    summary=(
                        f"Tool '{tool_name}' description contains scope-overload keywords: "
                        f"{', '.join(found_overload_keywords)}. Tools that do 'everything' "
                        "are difficult to test, maintain, and use reliably."
                    ),
                    threat_category="OVERLOADED_TOOL_SCOPE",
                    details={
                        "tool_name": tool_name,
                        "rule_id": "HEUR-010",
                        "location": f"tool.{tool_name}.description",
                        "keywords": found_overload_keywords,
                        "recommendation": (
                            "Split into multiple focused tools, each with a specific, "
                            "well-defined purpose"
                        ),
                    },
                )
            )

        # Check for too many action verbs
        action_verbs = [
            "create",
            "read",
            "write",
            "update",
            "delete",
            "get",
            "set",
            "fetch",
            "send",
            "post",
            "put",
            "patch",
            "remove",
            "add",
            "list",
            "find",
            "search",
            "query",
            "execute",
            "run",
            "start",
            "stop",
            "restart",
            "pause",
            "resume",
            "cancel",
            "retry",
        ]

        found_verbs = [verb for verb in action_verbs if verb in description]

        if len(found_verbs) > 5:
            findings.append(
                self.create_security_finding(
                    severity="HIGH",
                    summary=(
                        f"Tool '{tool_name}' description mentions {len(found_verbs)} action verbs "
                        f"(found: {', '.join(found_verbs[:5])}...). Tools with many capabilities "
                        "are harder to test, secure, and maintain."
                    ),
                    threat_category="OVERLOADED_TOOL_SCOPE",
                    details={
                        "tool_name": tool_name,
                        "rule_id": "HEUR-010",
                        "location": f"tool.{tool_name}.description",
                        "verb_count": len(found_verbs),
                        "verbs": found_verbs,
                        "recommendation": (
                            "Consider splitting into multiple focused tools "
                            "with specific responsibilities"
                        ),
                    },
                )
            )

        return findings

    # ===================================================================
    # HEUR-011: No required fields (LOW)
    # ===================================================================
    def _check_no_required_fields(
        self, tool_def: Dict[str, Any], tool_name: str
    ) -> List[SecurityFinding]:
        """HEUR-011: Check if inputSchema exists but no 'required' array is defined."""
        findings: List[SecurityFinding] = []

        input_schema = tool_def.get("inputSchema")

        if input_schema and isinstance(input_schema, dict):
            properties = input_schema.get("properties", {})
            required = input_schema.get("required", [])

            # Only flag if there are properties but no required fields
            if properties and not required:
                findings.append(
                    self.create_security_finding(
                        severity="LOW",
                        summary=(
                            f"Tool '{tool_name}' has an input schema with {len(properties)} "
                            "properties but doesn't specify which fields are required. "
                            "This may lead to missing input errors at runtime."
                        ),
                        threat_category="SILENT_FAILURE_PATH",
                        details={
                            "tool_name": tool_name,
                            "rule_id": "HEUR-011",
                            "location": f"tool.{tool_name}.inputSchema.required",
                            "property_count": len(properties),
                            "recommendation": (
                                "Add a 'required' array listing mandatory input fields"
                            ),
                        },
                    )
                )

        return findings

    # ===================================================================
    # HEUR-012: No input validation hints (INFO)
    # ===================================================================
    def _check_no_input_validation_hints(
        self, tool_def: Dict[str, Any], tool_name: str
    ) -> List[SecurityFinding]:
        """HEUR-012: Check if inputSchema properties lack validation keywords."""
        findings: List[SecurityFinding] = []

        input_schema = tool_def.get("inputSchema")

        if input_schema and isinstance(input_schema, dict):
            properties = input_schema.get("properties", {})

            if properties:
                validation_keywords = [
                    "pattern",
                    "minLength",
                    "maxLength",
                    "minimum",
                    "maximum",
                    "enum",
                    "format",
                    "minItems",
                    "maxItems",
                ]

                properties_without_validation = []
                for prop_name, prop_def in properties.items():
                    if isinstance(prop_def, dict):
                        has_validation = any(
                            kw in prop_def for kw in validation_keywords
                        )
                        if not has_validation:
                            properties_without_validation.append(prop_name)

                if (
                    properties_without_validation
                    and len(properties_without_validation) >= len(properties) * 0.5
                ):
                    findings.append(
                        self.create_security_finding(
                            severity="INFO",
                            summary=(
                                f"Tool '{tool_name}' input schema has "
                                f"{len(properties_without_validation)} properties "
                                f"(out of {len(properties)}) without validation constraints. "
                                "This may allow invalid inputs."
                            ),
                            threat_category="SILENT_FAILURE_PATH",
                            details={
                                "tool_name": tool_name,
                                "rule_id": "HEUR-012",
                                "location": f"tool.{tool_name}.inputSchema.properties",
                                "properties_without_validation": properties_without_validation[
                                    :5
                                ],
                                "total_properties": len(properties),
                                "recommendation": (
                                    "Add validation constraints to input properties "
                                    "(e.g., pattern for strings, minimum/maximum for numbers)"
                                ),
                            },
                        )
                    )

        return findings

    # ===================================================================
    # HEUR-013: No rate limit (LOW)
    # ===================================================================
    def _check_no_rate_limit(
        self, tool_def: Dict[str, Any], tool_name: str
    ) -> List[SecurityFinding]:
        """HEUR-013: Check for missing rate limit configuration."""
        findings: List[SecurityFinding] = []

        rate_limit_fields = [
            "rateLimit",
            "rate_limit",
            "rateLimitPerMinute",
            "throttle",
            "maxCallsPerSecond",
        ]
        has_rate_limit = any(field in tool_def for field in rate_limit_fields)

        config = self._mapping(tool_def.get("config"))
        has_rate_limit = has_rate_limit or any(
            field in config for field in rate_limit_fields
        )

        if not has_rate_limit:
            findings.append(
                self.create_security_finding(
                    severity="LOW",
                    summary=(
                        f"Tool '{tool_name}' does not specify rate limits. "
                        "Without rate limits, rapid repeated calls may overwhelm "
                        "external services or exhaust resources."
                    ),
                    threat_category="UNSAFE_RETRY_LOOP",
                    details={
                        "tool_name": tool_name,
                        "rule_id": "HEUR-013",
                        "location": f"tool.{tool_name}",
                        "recommendation": (
                            "Add a 'rateLimit' field specifying maximum calls per time period"
                        ),
                    },
                )
            )

        return findings

    # ===================================================================
    # HEUR-014: No version (LOW)
    # ===================================================================
    def _check_no_version(
        self, tool_def: Dict[str, Any], tool_name: str
    ) -> List[SecurityFinding]:
        """HEUR-014: Check for missing version information."""
        findings: List[SecurityFinding] = []

        version_fields = ["version", "apiVersion", "api_version", "schemaVersion"]
        has_version = any(field in tool_def for field in version_fields)

        if not has_version:
            findings.append(
                self.create_security_finding(
                    severity="LOW",
                    summary=(
                        f"Tool '{tool_name}' does not specify a version. "
                        "Versioning helps track changes and ensure compatibility "
                        "when tools evolve over time."
                    ),
                    threat_category="NO_OBSERVABILITY_HOOKS",
                    details={
                        "tool_name": tool_name,
                        "rule_id": "HEUR-014",
                        "location": f"tool.{tool_name}",
                        "recommendation": (
                            "Add a 'version' field (e.g., '1.0.0') following semantic versioning"
                        ),
                    },
                )
            )

        return findings

    # ===================================================================
    # HEUR-015: No observability config (LOW)
    # ===================================================================
    def _check_no_observability(
        self, tool_def: Dict[str, Any], tool_name: str
    ) -> List[SecurityFinding]:
        """HEUR-015: Check for missing observability/monitoring configuration."""
        findings: List[SecurityFinding] = []

        observability_fields = [
            "observability",
            "logging",
            "metrics",
            "telemetry",
            "tracing",
            "monitoring",
            "instrumentation",
            "logger",
        ]
        has_observability = any(field in tool_def for field in observability_fields)

        config = self._mapping(tool_def.get("config"))
        has_observability = has_observability or any(
            field in config for field in observability_fields
        )

        if not has_observability:
            findings.append(
                self.create_security_finding(
                    severity="LOW",
                    summary=(
                        f"Tool '{tool_name}' does not configure observability hooks "
                        "(logging, metrics, tracing). Without observability, "
                        "debugging production issues becomes extremely difficult."
                    ),
                    threat_category="NO_OBSERVABILITY_HOOKS",
                    details={
                        "tool_name": tool_name,
                        "rule_id": "HEUR-015",
                        "location": f"tool.{tool_name}",
                        "recommendation": (
                            "Add logging, metrics, or tracing configuration to enable "
                            "monitoring and debugging in production"
                        ),
                    },
                )
            )

        return findings

    # ===================================================================
    # HEUR-016: Resource cleanup not documented (MEDIUM)
    # ===================================================================
    def _check_resource_cleanup_not_documented(
        self, tool_def: Dict[str, Any], tool_name: str
    ) -> List[SecurityFinding]:
        """HEUR-016: Check if description mentions resources but not cleanup."""
        findings: List[SecurityFinding] = []

        description = self._description(tool_def).lower()

        # Check if tool appears to use resources that need cleanup
        resource_indicators = [
            "connection",
            "file",
            "stream",
            "socket",
            "handle",
            "session",
            "lock",
            "transaction",
            "database",
            "network",
        ]
        uses_resources = any(indicator in description for indicator in resource_indicators)

        if uses_resources:
            # Check if cleanup is documented
            cleanup_indicators = [
                "close",
                "cleanup",
                "release",
                "dispose",
                "free",
                "disconnect",
            ]
            has_cleanup_doc = any(
                indicator in description for indicator in cleanup_indicators
            )

            if not has_cleanup_doc:
                found_resources = [
                    ind for ind in resource_indicators if ind in description
                ]
                findings.append(
                    self.create_security_finding(
                        severity="MEDIUM",
                        summary=(
                            f"Tool '{tool_name}' appears to use resources "
                            f"({', '.join(found_resources[:3])}) but doesn't document "
                            "cleanup procedures. Resource leaks can cause production instability."
                        ),
                        threat_category="SILENT_FAILURE_PATH",
                        details={
                            "tool_name": tool_name,
                            "rule_id": "HEUR-016",
                            "location": f"tool.{tool_name}.description",
                            "resources": found_resources,
                            "recommendation": (
                                "Document how resources are cleaned up (e.g., 'connections "
                                "are automatically closed', 'call cleanup() to release resources')"
                            ),
                        },
                    )
                )

        return findings

    # ===================================================================
    # HEUR-017: No idempotency indication (INFO)
    # ===================================================================
    def _check_no_idempotency_indication(
        self, tool_def: Dict[str, Any], tool_name: str
    ) -> List[SecurityFinding]:
        """HEUR-017: Check if tool appears to modify state but doesn't document idempotency."""
        findings: List[SecurityFinding] = []

        description = self._description(tool_def).lower()

        # Check if tool appears to be state-changing
        state_changing_verbs = [
            "create",
            "delete",
            "update",
            "modify",
            "remove",
            "insert",
            "write",
            "post",
            "put",
            "patch",
            "drop",
            "truncate",
        ]
        is_state_changing = any(verb in description for verb in state_changing_verbs)

        if is_state_changing:
            # Check if idempotency is documented
            idempotency_indicators = [
                "idempotent",
                "safe to retry",
                "can be retried",
                "idempotency",
                "duplicate",
                "repeat",
            ]
            has_idempotency_doc = any(
                indicator in description for indicator in idempotency_indicators
            )

            if not has_idempotency_doc:
                findings.append(
                    self.create_security_finding(
                        severity="INFO",
                        summary=(
                            f"Tool '{tool_name}' appears to perform state-changing operations "
                            "but doesn't indicate whether it's idempotent. This is important "
                            "for retry logic - non-idempotent operations may cause duplicates."
                        ),
                        threat_category="NON_DETERMINISTIC_RESPONSE",
                        details={
                            "tool_name": tool_name,
                            "rule_id": "HEUR-017",
                            "location": f"tool.{tool_name}.description",
                            "recommendation": (
                                "Document whether the operation is idempotent and safe to retry. "
                                "If not idempotent, consider adding idempotency keys."
                            ),
                        },
                    )
                )

        return findings

    # ===================================================================
    # HEUR-018: Dangerous operation keywords (HIGH)
    # ===================================================================
    def _check_dangerous_operation_keywords(
        self, tool_def: Dict[str, Any], tool_name: str
    ) -> List[SecurityFinding]:
        """HEUR-018: Check for dangerous keywords in name/description."""
        findings: List[SecurityFinding] = []

        name = self._text(tool_def.get("name")).lower()
        description = self._description(tool_def).lower()
        combined = f"{name} {description}"

        dangerous_keywords = [
            ("delete", "deletion operations"),
            ("drop", "drop/destroy operations"),
            ("truncate", "truncate operations"),
            ("exec", "code execution"),
            ("eval", "code evaluation"),
            ("rm ", "file removal"),
            ("remove", "removal operations"),
            ("destroy", "destruction operations"),
            ("purge", "purge operations"),
            ("wipe", "wipe operations"),
        ]

        found_dangerous = []
        for keyword, meaning in dangerous_keywords:
            if keyword in combined:
                found_dangerous.append((keyword, meaning))

        if found_dangerous:
            findings.append(
                self.create_security_finding(
                    severity="HIGH",
                    summary=(
                        f"Tool '{tool_name}' contains dangerous operation keywords: "
                        f"{', '.join(k for k, _ in found_dangerous)}. "
                        "Tools performing destructive operations require extra safeguards."
                    ),
                    threat_category="OVERLOADED_TOOL_SCOPE",
                    details={
                        "tool_name": tool_name,
                        "rule_id": "HEUR-018",
                        "location": f"tool.{tool_name}",
                        "keywords": [k for k, m in found_dangerous],
                        "recommendation": (
                            "Add safeguards: require explicit confirmation, implement dry-run mode, "
                            "add audit logging, or provide undo/rollback mechanisms"
                        ),
                    },
                )
            )

        return findings

    # ===================================================================
    # HEUR-019: No authentication context (INFO)
    # ===================================================================
    def _check_no_authentication_context(
        self, tool_def: Dict[str, Any], tool_name: str
    ) -> List[SecurityFinding]:
        """HEUR-019: Check if tool accesses external resources but has no auth config."""
        findings: List[SecurityFinding] = []

        auth_fields = [
            "auth",
            "authentication",
            "credentials",
            "apiKey",
            "api_key",
            "token",
        ]
        has_auth = any(field in tool_def for field in auth_fields)

        config = self._mapping(tool_def.get("config"))
        has_auth = has_auth or any(field in config for field in auth_fields)

        # Check if description mentions external services
        description = self._description(tool_def).lower()
        external_indicators = [
            "api",
            "service",
            "endpoint",
            "http",
            "rest",
            "request",
            "external",
            "remote",
            "third-party",
            "cloud",
            "server",
        ]
        mentions_external = any(
            indicator in description for indicator in external_indicators
        )

        if mentions_external and not has_auth:
            findings.append(
                self.create_security_finding(
                    severity="INFO",
                    summary=(
                        f"Tool '{tool_name}' appears to interact with external services "
                        "but does not document authentication requirements. This may lead "
                        "to authorization failures at runtime."
                    ),
                    threat_category="SILENT_FAILURE_PATH",
                    details={
                        "tool_name": tool_name,
                        "rule_id": "HEUR-019",
                        "location": f"tool.{tool_name}",
                        "recommendation": (
                            "Document authentication requirements (e.g., 'requires API_KEY "
                            "environment variable', 'auth' field, or credential configuration)"
                        ),
                    },
                )
            )

        return findings

    # ===================================================================
    # HEUR-020: Circular dependency risk (MEDIUM)
    # ===================================================================
    def _check_circular_dependency_risk(
        self, tool_def: Dict[str, Any], tool_name: str
    ) -> List[SecurityFinding]:
        """HEUR-020: Check if tool references itself or common circular patterns."""
        findings: List[SecurityFinding] = []

        description = self._description(tool_def).lower()

        # Check if tool name appears in its own description (potential self-reference)
        tool_label = self._text(tool_name).lower()
        if tool_label and tool_label in description:
            findings.append(
                self.create_security_finding(
                    severity="MEDIUM",
                    summary=(
                        f"Tool '{tool_name}' references itself in its description. "
                        "Self-referencing tools can cause infinite loops in agent workflows."
                    ),
                    threat_category="UNSAFE_RETRY_LOOP",
                    details={
                        "tool_name": tool_name,
                        "rule_id": "HEUR-020",
                        "location": f"tool.{tool_name}.description",
                        "recommendation": (
                            "Ensure the tool does not call itself recursively. "
                            "If recursive calls are necessary, implement depth limits."
                        ),
                    },
                )
            )

        # Check for circular dependency patterns
        circular_patterns = [
            ("calls itself", "self-referencing"),
            ("recursive", "recursion"),
            ("loop", "looping behavior"),
            ("repeat until", "unbounded repetition"),
        ]

        for pattern, meaning in circular_patterns:
            if pattern in description:
                findings.append(
                    self.create_security_finding(
                        severity="MEDIUM",
                        summary=(
                            f"Tool '{tool_name}' description mentions {meaning}. "
                            "Ensure proper termination conditions to avoid infinite loops."
                        ),
                        threat_category="UNSAFE_RETRY_LOOP",
                        details={
                            "tool_name": tool_name,
                            "rule_id": "HEUR-020",
                            "location": f"tool.{tool_name}.description",
                            "pattern": pattern,
                            "meaning": meaning,
                            "recommendation": (
                                "Add explicit termination conditions, maximum iteration counts, "
                                "or depth limits to prevent infinite loops"
                            ),
                        },
                    )
                )
                break  # Only report once

        return findings
