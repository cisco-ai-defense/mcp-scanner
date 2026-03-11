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

"""Deterministic rule engine for MCP tool classification.

Operates on FunctionContext from static analysis to produce findings
without any LLM calls. Each rule inspects dataflow, taint, imports,
function calls, and boolean flags to decide if a threat is present.
"""

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from ...utils.logging_config import get_logger
from ..static_analysis.context_extractor import FunctionContext

logger = get_logger(__name__)

# Patterns for suspicious external URLs
_EXTERNAL_URL_RE = re.compile(
    r"https?://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|::1|\[::1\])"
)

# Known dangerous modules/functions for subprocess execution
_SUBPROCESS_SINKS = {
    "subprocess.run",
    "subprocess.call",
    "subprocess.Popen",
    "subprocess.check_output",
    "subprocess.check_call",
    "os.system",
    "os.popen",
    "os.exec",
    "os.execvp",
    "os.execve",
    "os.spawnl",
    "os.spawnle",
}

# Known network sending functions
_NETWORK_SEND_SINKS = {
    "requests.post",
    "requests.put",
    "requests.patch",
    "requests.delete",
    "httpx.post",
    "httpx.put",
    "httpx.patch",
    "httpx.delete",
    "urllib.request.urlopen",
    "aiohttp.ClientSession.post",
    "aiohttp.ClientSession.put",
}

# Known file write sinks
_FILE_WRITE_SINKS = {
    "open",
    "pathlib.Path.write_text",
    "pathlib.Path.write_bytes",
    "shutil.copy",
    "shutil.copy2",
    "shutil.move",
    "os.rename",
}

# Environment variable access patterns
_ENV_HARVEST_PATTERNS = {
    "os.environ",
    "os.getenv",
    "os.environ.get",
    "os.environ.items",
    "os.environ.keys",
    "os.environ.values",
}


@dataclass
class RuleMatch:
    """Result of a single rule match."""

    rule_id: str
    threat_name: str
    severity: str
    description: str
    evidence: List[str]


class DeterministicRule(ABC):
    """Base class for a deterministic detection rule."""

    rule_id: str = ""
    threat_name: str = ""
    severity: str = "HIGH"
    description: str = ""

    @abstractmethod
    def matches(self, ctx: FunctionContext) -> Optional[RuleMatch]:
        """Evaluate this rule against a FunctionContext.

        Returns a RuleMatch if the rule triggers, else None.
        """


class TaintedSubprocessExec(DeterministicRule):
    """Detects MCP parameters flowing into subprocess/os.system calls."""

    rule_id = "DET-001"
    threat_name = "UNAUTHORIZED OR UNSOLICITED CODE EXECUTION"
    severity = "HIGH"
    description = "MCP parameter flows into subprocess or os.system call"

    def matches(self, ctx: FunctionContext) -> Optional[RuleMatch]:
        if not ctx.has_subprocess_calls:
            return None

        evidence = []

        # Check parameter flows reaching subprocess calls
        for flow in ctx.parameter_flows:
            for call in flow.get("reaches_calls", []):
                call_name = call if isinstance(call, str) else call.get("name", "")
                if any(sink in call_name for sink in _SUBPROCESS_SINKS):
                    evidence.append(
                        f"Parameter '{flow['parameter']}' flows to {call_name}"
                    )

        # Also check function_calls directly for subprocess with variable args
        if not evidence:
            param_names = {p["name"] for p in ctx.parameters}
            for call in ctx.function_calls:
                call_name = call.get("name", "")
                if any(sink in call_name for sink in _SUBPROCESS_SINKS):
                    for arg in call.get("args", []):
                        if any(pn in arg for pn in param_names):
                            evidence.append(
                                f"Subprocess call {call_name} uses parameter in args: {arg}"
                            )

        if evidence:
            return RuleMatch(
                rule_id=self.rule_id,
                threat_name=self.threat_name,
                severity=self.severity,
                description=self.description,
                evidence=evidence,
            )
        return None


class TaintedEvalExec(DeterministicRule):
    """Detects MCP parameters flowing into eval/exec/compile."""

    rule_id = "DET-002"
    threat_name = "UNAUTHORIZED OR UNSOLICITED CODE EXECUTION"
    severity = "HIGH"
    description = "MCP parameter flows into eval, exec, or compile"

    def matches(self, ctx: FunctionContext) -> Optional[RuleMatch]:
        if not ctx.has_eval_exec:
            return None

        evidence = []
        dangerous_calls = {"eval", "exec", "compile", "__import__"}

        for flow in ctx.parameter_flows:
            for call in flow.get("reaches_calls", []):
                call_name = call if isinstance(call, str) else call.get("name", "")
                if call_name in dangerous_calls:
                    evidence.append(
                        f"Parameter '{flow['parameter']}' flows to {call_name}()"
                    )

        if not evidence:
            param_names = {p["name"] for p in ctx.parameters}
            for call in ctx.function_calls:
                call_name = call.get("name", "")
                if call_name in dangerous_calls:
                    for arg in call.get("args", []):
                        if any(pn in arg for pn in param_names):
                            evidence.append(
                                f"{call_name}() called with parameter-derived arg: {arg}"
                            )

        if evidence:
            return RuleMatch(
                rule_id=self.rule_id,
                threat_name=self.threat_name,
                severity=self.severity,
                description=self.description,
                evidence=evidence,
            )
        return None


class TaintedNetworkSend(DeterministicRule):
    """Detects MCP parameters flowing into outbound network calls."""

    rule_id = "DET-003"
    threat_name = "DATA EXFILTRATION"
    severity = "HIGH"
    description = "MCP parameter data flows to outbound network call"

    def matches(self, ctx: FunctionContext) -> Optional[RuleMatch]:
        if not ctx.has_network_operations:
            return None

        evidence = []

        for flow in ctx.parameter_flows:
            reaches_external = flow.get("reaches_external", False)
            if reaches_external:
                evidence.append(
                    f"Parameter '{flow['parameter']}' reaches external call"
                )
                continue

            for call in flow.get("reaches_calls", []):
                call_name = call if isinstance(call, str) else call.get("name", "")
                if any(sink in call_name for sink in _NETWORK_SEND_SINKS):
                    evidence.append(
                        f"Parameter '{flow['parameter']}' flows to {call_name}"
                    )

        if not evidence:
            param_names = {p["name"] for p in ctx.parameters}
            for call in ctx.function_calls:
                call_name = call.get("name", "")
                if any(sink in call_name for sink in _NETWORK_SEND_SINKS):
                    for arg in call.get("args", []):
                        if any(pn in arg for pn in param_names):
                            evidence.append(
                                f"Network call {call_name} uses parameter in args: {arg}"
                            )

        if evidence:
            return RuleMatch(
                rule_id=self.rule_id,
                threat_name=self.threat_name,
                severity=self.severity,
                description=self.description,
                evidence=evidence,
            )
        return None


class HardcodedExternalURL(DeterministicRule):
    """Detects hardcoded external URLs in tool code (potential C2 or exfil endpoints)."""

    rule_id = "DET-004"
    threat_name = "UNAUTHORIZED OR UNSOLICITED NETWORK ACCESS"
    severity = "MEDIUM"
    description = "Hardcoded external URL found in MCP tool code"

    def matches(self, ctx: FunctionContext) -> Optional[RuleMatch]:
        evidence = []

        for literal in ctx.string_literals:
            if _EXTERNAL_URL_RE.search(literal):
                evidence.append(f"Hardcoded URL: {literal[:120]}")

        if evidence:
            return RuleMatch(
                rule_id=self.rule_id,
                threat_name=self.threat_name,
                severity=self.severity,
                description=self.description,
                evidence=evidence,
            )
        return None


class TaintedFileWrite(DeterministicRule):
    """Detects MCP parameters flowing into file write operations."""

    rule_id = "DET-005"
    threat_name = "ARBITRARY RESOURCE READ/WRITE"
    severity = "MEDIUM"
    description = "MCP parameter flows into file write operation"

    def matches(self, ctx: FunctionContext) -> Optional[RuleMatch]:
        if not ctx.has_file_operations:
            return None

        evidence = []

        for flow in ctx.parameter_flows:
            for call in flow.get("reaches_calls", []):
                call_name = call if isinstance(call, str) else call.get("name", "")
                if any(sink in call_name for sink in _FILE_WRITE_SINKS):
                    evidence.append(
                        f"Parameter '{flow['parameter']}' flows to {call_name}"
                    )

        if not evidence:
            param_names = {p["name"] for p in ctx.parameters}
            for call in ctx.function_calls:
                call_name = call.get("name", "")
                if any(sink in call_name for sink in _FILE_WRITE_SINKS):
                    for arg in call.get("args", []):
                        if any(pn in arg for pn in param_names):
                            evidence.append(
                                f"File write {call_name} uses parameter: {arg}"
                            )

        if evidence:
            return RuleMatch(
                rule_id=self.rule_id,
                threat_name=self.threat_name,
                severity=self.severity,
                description=self.description,
                evidence=evidence,
            )
        return None


class EnvVarHarvesting(DeterministicRule):
    """Detects tools that read environment variables (potential credential harvesting)."""

    rule_id = "DET-006"
    threat_name = "DATA EXFILTRATION"
    severity = "MEDIUM"
    description = "MCP tool accesses environment variables"

    def matches(self, ctx: FunctionContext) -> Optional[RuleMatch]:
        if not ctx.env_var_access:
            return None

        # Only flag if env vars are accessed AND there are network operations
        # (reading env vars alone is common; sending them out is suspicious)
        if not ctx.has_network_operations:
            return None

        evidence = [f"Env var access: {ev}" for ev in ctx.env_var_access[:5]]
        evidence.append("Combined with network operations — potential credential exfiltration")

        return RuleMatch(
            rule_id=self.rule_id,
            threat_name=self.threat_name,
            severity=self.severity,
            description=self.description,
            evidence=evidence,
        )


class DocstringMismatchHeuristic(DeterministicRule):
    """Detects obvious mismatches between docstring claims and actual behavior.

    Uses keyword-based heuristics (no LLM). Flags cases where the docstring
    says the tool does X but the code clearly does Y.
    """

    rule_id = "DET-007"
    threat_name = "GENERAL DESCRIPTION-CODE MISMATCH"
    severity = "INFO"
    description = "Docstring claims do not match detected code behavior"

    # Docstring claims vs code reality checks
    _CLAIM_VS_REALITY = [
        {
            "claim_keywords": ["calculator", "math", "compute", "add", "sum", "multiply"],
            "suspicious_flags": ["has_network_operations", "has_subprocess_calls", "has_file_operations"],
            "message": "Math/calculator tool has {flag}",
        },
        {
            "claim_keywords": ["read", "get", "fetch", "query", "search", "lookup"],
            "suspicious_flags": ["has_subprocess_calls"],
            "message": "Read-only tool has subprocess calls",
        },
        {
            "claim_keywords": ["hello", "greet", "welcome", "ping", "echo"],
            "suspicious_flags": ["has_network_operations", "has_file_operations", "has_subprocess_calls"],
            "message": "Simple greeting/echo tool has {flag}",
        },
    ]

    def matches(self, ctx: FunctionContext) -> Optional[RuleMatch]:
        if not ctx.docstring:
            return None

        docstring_lower = ctx.docstring.lower()
        name_lower = ctx.name.lower()
        evidence = []

        for check in self._CLAIM_VS_REALITY:
            # See if docstring or function name matches claim keywords
            claim_match = any(
                kw in docstring_lower or kw in name_lower
                for kw in check["claim_keywords"]
            )
            if not claim_match:
                continue

            for flag in check["suspicious_flags"]:
                if getattr(ctx, flag, False):
                    msg = check["message"].format(flag=flag)
                    evidence.append(msg)

        if evidence:
            return RuleMatch(
                rule_id=self.rule_id,
                threat_name=self.threat_name,
                severity=self.severity,
                description=self.description,
                evidence=evidence,
            )
        return None


# Registry of all built-in rules
DEFAULT_RULES: List[DeterministicRule] = [
    TaintedSubprocessExec(),
    TaintedEvalExec(),
    TaintedNetworkSend(),
    HardcodedExternalURL(),
    TaintedFileWrite(),
    EnvVarHarvesting(),
    DocstringMismatchHeuristic(),
]


class DeterministicClassifier:
    """Runs all deterministic rules against a FunctionContext.

    Returns a list of RuleMatch objects for every rule that fires.
    """

    def __init__(self, rules: Optional[List[DeterministicRule]] = None):
        self.rules = rules if rules is not None else list(DEFAULT_RULES)

    def classify(self, ctx: FunctionContext) -> List[RuleMatch]:
        """Run all rules against the given context.

        Args:
            ctx: FunctionContext from static analysis

        Returns:
            List of RuleMatch for every rule that fired
        """
        matches = []
        for rule in self.rules:
            try:
                result = rule.matches(ctx)
                if result:
                    matches.append(result)
            except Exception as e:
                logger.warning(f"Rule {rule.rule_id} failed on {ctx.name}: {e}")
        return matches
