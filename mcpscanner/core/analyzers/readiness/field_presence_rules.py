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

"""Declarative form of the "tool declares none of these fields" heuristics.

Seven of the twenty readiness rules say the same thing about different field
names: look for any of a set of keys on the tool definition (and usually in
its nested ``config``), and raise one finding when none are present. Written
out longhand each was thirty near-identical lines, which made the handful of
real differences — whether ``config`` is consulted, whether a ``retryPolicy``
object counts — invisible.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Tuple


@dataclass(frozen=True)
class FieldPresenceRule:
    """One "this configuration is missing" readiness heuristic."""

    #: HEUR-nnn identifier reported in the finding details.
    rule_id: str
    #: Any one of these keys present means the tool satisfies the rule.
    fields: Tuple[str, ...]
    severity: str
    threat_category: str
    #: Finding summary; ``{tool}`` is substituted with the tool name.
    summary: str
    recommendation: str
    #: Whether a nested ``config`` object also satisfies the rule.
    check_config: bool = True
    #: Whether a nested ``retryPolicy`` object also satisfies it (HEUR-003).
    check_retry_policy: bool = False

    def is_satisfied(self, tool_def: Dict[str, Any]) -> bool:
        """Whether ``tool_def`` declares at least one of the rule's fields."""
        scopes: list[Any] = [tool_def]
        if self.check_config:
            scopes.append(tool_def.get("config", {}))
        if self.check_retry_policy:
            config = tool_def.get("config", {})
            scopes.append(tool_def.get("retryPolicy") or config.get("retryPolicy"))
        return any(
            isinstance(scope, dict) and any(field in scope for field in self.fields)
            for scope in scopes
        )


FIELD_PRESENCE_RULES: Dict[str, FieldPresenceRule] = {
    rule.rule_id: rule
    for rule in (
        FieldPresenceRule(
            rule_id="HEUR-001",
            fields=("timeout", "timeoutMs", "timeout_ms", "timeoutSeconds"),
            severity="HIGH",
            threat_category="MISSING_TIMEOUT_GUARD",
            summary=(
                "Tool '{tool}' does not specify a timeout. "
                "Operations may hang indefinitely if external services "
                "become unresponsive."
            ),
            recommendation=(
                "Add a 'timeout' or 'timeoutMs' field with a reasonable "
                "value (e.g., 30000 for 30 seconds)"
            ),
        ),
        FieldPresenceRule(
            rule_id="HEUR-003",
            fields=(
                "maxRetries",
                "retries",
                "max_retries",
                "retryCount",
                "retryLimit",
                "retry_limit",
            ),
            severity="MEDIUM",
            threat_category="UNSAFE_RETRY_LOOP",
            summary=(
                "Tool '{tool}' does not specify a retry limit. "
                "Without limits, retry logic may cause resource exhaustion "
                "or infinite loops."
            ),
            recommendation=(
                "Add a 'maxRetries' or 'retryLimit' field with a "
                "reasonable value (e.g., 3)"
            ),
            check_retry_policy=True,
        ),
        FieldPresenceRule(
            rule_id="HEUR-006",
            fields=("errorSchema", "error_schema", "errors", "errorResponse"),
            severity="MEDIUM",
            threat_category="MISSING_ERROR_SCHEMA",
            summary=(
                "Tool '{tool}' does not define an error response schema. "
                "Without structured error responses, agents cannot "
                "programmatically handle failures."
            ),
            recommendation=(
                "Add an 'errorSchema' field defining the structure of "
                "error responses with error codes and messages"
            ),
            check_config=False,
        ),
        FieldPresenceRule(
            rule_id="HEUR-008",
            fields=(
                "outputSchema",
                "output_schema",
                "responseSchema",
                "response_schema",
            ),
            severity="LOW",
            threat_category="MISSING_ERROR_SCHEMA",
            summary=(
                "Tool '{tool}' does not define an output schema. "
                "Agents cannot reliably parse responses without knowing "
                "the expected structure."
            ),
            recommendation=(
                "Add an 'outputSchema' field defining the structure "
                "of successful responses"
            ),
            check_config=False,
        ),
        FieldPresenceRule(
            rule_id="HEUR-013",
            fields=(
                "rateLimit",
                "rate_limit",
                "rateLimitPerMinute",
                "throttle",
                "maxCallsPerSecond",
            ),
            severity="LOW",
            threat_category="UNSAFE_RETRY_LOOP",
            summary=(
                "Tool '{tool}' does not specify rate limits. "
                "Without rate limits, rapid repeated calls may overwhelm "
                "external services or exhaust resources."
            ),
            recommendation=(
                "Add a 'rateLimit' field specifying maximum calls per time period"
            ),
        ),
        FieldPresenceRule(
            rule_id="HEUR-014",
            fields=("version", "apiVersion", "api_version", "schemaVersion"),
            severity="LOW",
            threat_category="NO_OBSERVABILITY_HOOKS",
            summary=(
                "Tool '{tool}' does not specify a version. "
                "Versioning helps track changes and ensure compatibility "
                "when tools evolve over time."
            ),
            recommendation=(
                "Add a 'version' field (e.g., '1.0.0') following semantic versioning"
            ),
            check_config=False,
        ),
        FieldPresenceRule(
            rule_id="HEUR-015",
            fields=(
                "observability",
                "logging",
                "metrics",
                "telemetry",
                "tracing",
                "monitoring",
                "instrumentation",
                "logger",
            ),
            severity="LOW",
            threat_category="NO_OBSERVABILITY_HOOKS",
            summary=(
                "Tool '{tool}' does not configure observability hooks "
                "(logging, metrics, tracing). Without observability, "
                "debugging production issues becomes extremely difficult."
            ),
            recommendation=(
                "Add logging, metrics, or tracing configuration to enable "
                "monitoring and debugging in production"
            ),
        ),
    )
}
