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

import ast
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set

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


# ── Dangerous imports/calls for file-scope scanning (DET-008) ──
# Sourced from cisco-sbg/ai-common-py modelhawk security constants

_DANGEROUS_BUILTINS = {
    "eval", "exec", "compile", "execfile", "__import__", "globals",
}

_DANGEROUS_MODULE_FUNCTIONS = {
    "os.system", "os.popen", "os.fork", "os.exec", "os.execl", "os.execlp",
    "os.execle", "os.execv", "os.execve", "os.execvp", "os.execvpe",
    "os.spawn", "os.spawnl", "os.spawnle", "os.spawnlp", "os.spawnlpe",
    "os.spawnv", "os.spawnve", "os.spawnvp", "os.spawnvpe",
    "subprocess.Popen", "subprocess.call", "subprocess.check_call",
    "subprocess.check_output", "subprocess.run",
    "commands.getoutput", "commands.getstatusoutput",
    "pty.spawn",
    "posix.system", "posix.popen", "posix.fork",
    "asyncio.create_subprocess_shell", "asyncio.create_subprocess_exec",
}

_DANGEROUS_SERIALIZATION = {
    "pickle.loads", "pickle.load", "cPickle.loads", "cPickle.load",
    "dill.loads", "dill.load", "marshal.loads", "marshal.load",
    "shelve.open", "yaml.unsafe_load", "yaml.full_load", "yaml.load",
}

_DANGEROUS_NETWORK_SEND = {
    "requests.post", "requests.put", "requests.patch", "requests.delete",
    "httpx.post", "httpx.put", "httpx.patch", "httpx.delete",
    "urllib.request.urlopen", "urllib.request.Request",
    "smtplib.SMTP", "ftplib.FTP",
    "socket.connect", "socket.send", "socket.sendto", "socket.sendall",
}

_ALL_DANGEROUS_CALLS = (
    _DANGEROUS_BUILTINS
    | _DANGEROUS_MODULE_FUNCTIONS
    | _DANGEROUS_SERIALIZATION
    | _DANGEROUS_NETWORK_SEND
)


class FileScopeDangerousCall(DeterministicRule):
    """Detects dangerous calls anywhere in the same module as an MCP tool.

    Catches the helper-class pattern where malicious code is in a class method
    that the tool function calls indirectly.
    """

    rule_id = "DET-008"
    threat_name = "UNAUTHORIZED OR UNSOLICITED CODE EXECUTION"
    severity = "MEDIUM"
    description = "Dangerous call found in module reachable from MCP tool"

    def matches(self, ctx: FunctionContext) -> Optional[RuleMatch]:
        # This rule uses module_dangerous_calls injected by interprocedural merge
        module_calls = getattr(ctx, "_module_dangerous_calls", None)
        if not module_calls:
            return None

        evidence = [f"Module contains: {call}" for call in sorted(module_calls)[:8]]

        # Determine severity based on what was found
        has_exec = any(
            c in module_calls
            for c in ("eval", "exec", "compile", "os.system", "os.fork",
                      "subprocess.run", "subprocess.Popen", "subprocess.call",
                      "pty.spawn")
        )
        sev = "HIGH" if has_exec else "MEDIUM"

        # Determine best threat name
        has_net = any(c in module_calls for c in _DANGEROUS_NETWORK_SEND)
        has_serial = any(c in module_calls for c in _DANGEROUS_SERIALIZATION)
        threat = self.threat_name
        if has_serial:
            threat = "UNAUTHORIZED OR UNSOLICITED CODE EXECUTION"
        elif has_net and not has_exec:
            threat = "DATA EXFILTRATION"

        return RuleMatch(
            rule_id=self.rule_id,
            threat_name=threat,
            severity=sev,
            description=self.description,
            evidence=evidence,
        )


# ── Resource Exhaustion (DET-009) — strict patterns only ──

_FORK_BOMB_SHELL_PATTERNS = [
    ":(){ :|:& };:",           # bash fork bomb
    "fork()",                   # not enough alone
    "bash -c",
    "/dev/tcp/",
]


class ResourceExhaustion(DeterministicRule):
    """Detects intentional resource exhaustion: fork bombs and infinite spawn loops.

    Only fires on high-confidence patterns to avoid false positives.
    """

    rule_id = "DET-009"
    threat_name = "RESOURCE EXHAUSTION"
    severity = "HIGH"
    description = "Intentional resource exhaustion pattern detected"

    def matches(self, ctx: FunctionContext) -> Optional[RuleMatch]:
        evidence = []
        module_calls = getattr(ctx, "_module_dangerous_calls", set())

        # Pattern 1: os.fork() present in reachable code
        if "os.fork" in module_calls:
            evidence.append("os.fork() in reachable code — potential fork bomb")

        # Pattern 2: fork bomb shell strings
        for literal in getattr(ctx, "_module_string_literals", ctx.string_literals):
            for pattern in _FORK_BOMB_SHELL_PATTERNS:
                if pattern in literal:
                    evidence.append(f"Fork bomb shell pattern: '{literal[:60]}'")
                    break

        # Pattern 3: multiprocessing.Process/Pool in reachable code
        # (only flag if combined with suspicious loop patterns)
        if "multiprocessing.Process" in module_calls or "multiprocessing.Pool" in module_calls:
            # Only flag if there's also indication of unbounded spawning
            has_loop = ctx.control_flow.get("has_loops", False)
            if has_loop:
                evidence.append("multiprocessing spawn inside loop")

        if evidence:
            return RuleMatch(
                rule_id=self.rule_id,
                threat_name=self.threat_name,
                severity=self.severity,
                description=self.description,
                evidence=evidence,
            )
        return None


# ── Template Injection (DET-010) ──

_TEMPLATE_SINKS = {
    "jinja2.Template",
    "jinja2.Environment",
    "jinja2.from_string",
    "mako.template.Template",
    "django.template.Template",
    "tornado.template.Template",
    "Cheetah.Template.Template",
    "string.Template",
    "Template",
}

_TEMPLATE_RENDER = {
    "render", "render_unicode", "render_body",
    "from_string", "generate",
}


class TemplateInjection(DeterministicRule):
    """Detects template engine usage with user-controlled template strings."""

    rule_id = "DET-010"
    threat_name = "TEMPLATE INJECTION"
    severity = "HIGH"
    description = "User input flows into template engine rendering"

    def matches(self, ctx: FunctionContext) -> Optional[RuleMatch]:
        evidence = []
        all_calls = getattr(ctx, "_module_function_calls", ctx.function_calls)

        # Check for template construction with param-derived strings
        param_names = {p["name"] for p in ctx.parameters}

        for call in all_calls:
            call_name = call.get("name", "")

            # Direct template construction: Template(user_input)
            if any(sink in call_name for sink in _TEMPLATE_SINKS):
                for arg in call.get("args", []):
                    if any(pn in arg for pn in param_names):
                        evidence.append(
                            f"Template constructor {call_name} uses parameter: {arg}"
                        )

            # Template.render / from_string with user input
            if any(call_name.endswith(f".{m}") for m in _TEMPLATE_RENDER):
                for arg in call.get("args", []):
                    if any(pn in arg for pn in param_names):
                        evidence.append(
                            f"Template render {call_name} uses parameter: {arg}"
                        )

        # Also check parameter flows for template sinks
        for flow in ctx.parameter_flows:
            for call in flow.get("reaches_calls", []):
                call_name = call if isinstance(call, str) else call.get("name", "")
                if any(sink in call_name for sink in _TEMPLATE_SINKS):
                    evidence.append(
                        f"Parameter '{flow['parameter']}' flows to {call_name}"
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


# ── Sensitive File Paths (DET-011) ──

_SENSITIVE_SYSTEM_PATHS = [
    "/etc/shadow", "/etc/passwd", "/etc/sudoers", "/etc/hosts",
    "/etc/cron", "/etc/ssh/", "/etc/ssl/",
    "~/.ssh/", ".ssh/authorized_keys", ".ssh/id_rsa", ".ssh/id_ed25519",
    "/proc/", "/sys/", "/dev/",
    "/var/log/", "/var/run/", "/var/spool/cron",
]

_SENSITIVE_CREDENTIAL_PATHS = [
    ".env", ".aws/credentials", ".aws/config",
    ".kube/config", "kubeconfig",
    ".docker/config.json",
    ".npmrc", ".pypirc", ".netrc",
    ".git-credentials", ".gitconfig",
    ".bash_history", ".zsh_history",
]

_SENSITIVE_IDE_CONFIG_PATHS = [
    # Cursor
    ".cursor/mcp.json", ".cursor/", "cursor_config",
    # Claude Code
    ".claude/", "claude_desktop_config.json", "claude.json",
    # Windsurf
    ".windsurf/", "windsurf_config",
    # VS Code
    ".vscode/settings.json", ".vscode/launch.json",
    # JetBrains
    ".idea/", ".idea/workspace.xml",
    # General
    ".editorconfig",
]

_CLOUD_METADATA_URLS = [
    "169.254.169.254",  # AWS/GCP/Azure metadata
    "metadata.google.internal",
    "metadata.azure.com",
    "100.100.100.200",  # Alibaba Cloud metadata
]

_ALL_SENSITIVE_PATHS = (
    _SENSITIVE_SYSTEM_PATHS
    + _SENSITIVE_CREDENTIAL_PATHS
    + _SENSITIVE_IDE_CONFIG_PATHS
    + _CLOUD_METADATA_URLS
)


class SensitiveFilePath(DeterministicRule):
    """Detects references to sensitive system files, credential stores,
    IDE configs, and cloud metadata endpoints in MCP tool code."""

    rule_id = "DET-011"
    threat_name = "UNAUTHORIZED OR UNSOLICITED SYSTEM ACCESS"
    severity = "MEDIUM"
    description = "Sensitive file path or cloud metadata URL found in MCP tool code"

    def matches(self, ctx: FunctionContext) -> Optional[RuleMatch]:
        evidence = []
        all_literals = getattr(
            ctx, "_module_string_literals", ctx.string_literals
        )

        for literal in all_literals:
            literal_lower = literal.lower()
            for sensitive in _ALL_SENSITIVE_PATHS:
                if sensitive.lower() in literal_lower:
                    # Categorize the match
                    if sensitive in _SENSITIVE_IDE_CONFIG_PATHS:
                        cat = "IDE config"
                    elif sensitive in _CLOUD_METADATA_URLS:
                        cat = "cloud metadata"
                    elif sensitive in _SENSITIVE_CREDENTIAL_PATHS:
                        cat = "credential file"
                    else:
                        cat = "system file"
                    evidence.append(f"{cat}: {literal[:100]}")
                    break  # One match per literal

        if evidence:
            # Escalate to HIGH if credential files or cloud metadata
            has_cred = any("credential" in e or "cloud metadata" in e for e in evidence)
            has_ide = any("IDE config" in e for e in evidence)
            sev = "HIGH" if (has_cred or has_ide) else self.severity

            return RuleMatch(
                rule_id=self.rule_id,
                threat_name=self.threat_name,
                severity=sev,
                description=self.description,
                evidence=evidence[:10],
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
    FileScopeDangerousCall(),
    ResourceExhaustion(),
    TemplateInjection(),
    SensitiveFilePath(),
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
