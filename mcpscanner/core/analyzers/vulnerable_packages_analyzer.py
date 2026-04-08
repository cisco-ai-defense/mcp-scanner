# Copyright 2026 Cisco Systems, Inc.
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
Vulnerable packages analyzer for scanning Python dependencies for known vulnerabilities.

Runs ``pip-audit`` as a subprocess with JSON output, parses the results,
and converts each vulnerability into a :class:`SecurityFinding`.

Dependencies:
  - ``pip-audit`` — installed in the same environment as mcp-scanner
"""

import json
import logging
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from ...threats.threats import ThreatMapping
from .base import SecurityFinding

logger = logging.getLogger(__name__)


class VulnerablePackagesAnalyzer:
    """Analyzer that checks Python dependencies for known vulnerabilities via pip-audit.

    Supports scanning:
      - A requirements file (``-r path``)
      - A project directory with ``pyproject.toml`` / lockfiles
      - An installed environment path (``--path``)
    """

    def __init__(
        self,
        enabled: bool = True,
        vulnerability_service: str = "pypi",
        timeout: int = 120,
        fix_mode: bool = False,
        desc: bool = True,
        skip_deps: bool = False,
        disable_pip: bool = False,
    ):
        self.enabled = enabled
        self.vulnerability_service = vulnerability_service
        self.timeout = timeout
        self.fix_mode = fix_mode
        self.desc = desc
        self.skip_deps = skip_deps
        self.disable_pip = disable_pip
        self.last_scan_summary: Optional[Dict[str, Any]] = None

        self._pip_audit_cmd = self._find_pip_audit()

        if self.enabled:
            cmd_label = " ".join(self._pip_audit_cmd) if self._pip_audit_cmd else "N/A"
            logger.info(
                "vulnerable-packages analyzer enabled (cmd=%s, service=%s, timeout=%ds)",
                cmd_label,
                self.vulnerability_service,
                self.timeout,
            )

    def _find_pip_audit(self) -> Optional[List[str]]:
        """Locate pip-audit, preferring the current venv, then PATH, then uv/uvx.

        Returns a command list (e.g. ``["/path/pip-audit"]`` or
        ``["uvx", "pip-audit"]``) or ``None`` if no viable option is found.
        """
        venv_bin = Path(sys.executable).parent / "pip-audit"
        if venv_bin.is_file():
            return [str(venv_bin)]

        found = shutil.which("pip-audit")
        if found:
            return [found]

        uvx = shutil.which("uvx")
        if uvx:
            return [uvx, "pip-audit"]

        uv = shutil.which("uv")
        if uv:
            return [uv, "tool", "run", "pip-audit"]

        logger.warning(
            "pip-audit not found; install with: pip install pip-audit  "
            "or  uv tool install pip-audit"
        )
        return None

    def analyze_requirements(self, requirements_path: str) -> List[SecurityFinding]:
        """Scan a requirements file for vulnerable dependencies.

        By default pip-audit resolves transitive dependencies.  Pass
        ``skip_deps=True`` / ``disable_pip=True`` at init time to restrict
        the scan to only the packages listed in the file (useful for
        fully-resolved or pinned inputs).
        """
        if not self.enabled:
            return []
        path = Path(requirements_path)
        if not path.is_file():
            logger.warning("Requirements file does not exist: %s", requirements_path)
            return []
        args = ["-r", str(path)]
        if self.skip_deps:
            args.append("--no-deps")
        if self.disable_pip:
            args.append("--disable-pip")
        return self._run_and_parse(args, source=str(path))

    def analyze_path(self, target_path: str) -> List[SecurityFinding]:
        """Scan a project directory, requirements file, or installed environment.

        Heuristics:
          - File ending in ``.txt`` or ``.in`` → requirements file scan.
          - Directory with ``requirements.txt`` → requirements file scan.
          - Directory with ``pyproject.toml`` and a ``.venv`` → installed
            environment scan via ``--path .venv``.
          - Directory with ``pyproject.toml`` (no ``.venv``) → project scan
            via positional arg (``pip-audit <dir>``).
          - Any other directory → installed environment scan via ``--path``.
        """
        if not self.enabled:
            return []

        p = Path(target_path)

        if p.is_file() and p.suffix in (".txt", ".in"):
            return self.analyze_requirements(str(p))

        if p.is_dir():
            req_file = p / "requirements.txt"
            if req_file.is_file():
                return self.analyze_requirements(str(req_file))

            pyproject = p / "pyproject.toml"
            if pyproject.is_file():
                venv = p / ".venv"
                if venv.is_dir():
                    args = ["--path", str(venv)]
                else:
                    args = [str(p)]
                return self._run_and_parse(args, source=str(p))

            args = ["--path", str(p)]
            return self._run_and_parse(args, source=str(p))

        logger.warning("Path does not exist or is unsupported: %s", target_path)
        return []

    def _run_and_parse(
        self, extra_args: List[str], source: str
    ) -> List[SecurityFinding]:
        """Execute pip-audit and convert JSON output to SecurityFindings."""
        if not self._pip_audit_cmd:
            logger.error("pip-audit binary not available; cannot scan")
            return []

        cmd = list(self._pip_audit_cmd) + [
            "--format", "json",
            "--vulnerability-service", self.vulnerability_service,
        ]
        if self.desc:
            cmd.append("--desc")
        if self.fix_mode:
            cmd.append("--fix")
        cmd.extend(extra_args)

        logger.info("Running: %s", " ".join(cmd))

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
        except subprocess.TimeoutExpired:
            logger.error("pip-audit timed out after %ds", self.timeout)
            return []
        except FileNotFoundError:
            logger.error(
                "pip-audit binary not found at: %s",
                self._pip_audit_cmd[0],
            )
            return []

        stdout = result.stdout.strip()
        stderr = result.stderr.strip()

        if result.returncode != 0 and not stdout:
            logger.warning(
                "pip-audit exited with code %d and produced no JSON output",
                result.returncode,
            )
            if stderr:
                error_hint = self._extract_error_hint(stderr)
                logger.warning("pip-audit error: %s", error_hint)
                if self._is_resolution_failure(stderr):
                    logger.warning(
                        "This looks like a dependency-resolution failure. "
                        "Try re-running with --no-deps --disable-pip to "
                        "scan only the explicitly listed packages."
                    )
            return []

        if stderr:
            for line in stderr.splitlines():
                logger.debug("pip-audit stderr: %s", line)

        if not stdout:
            return []

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError as e:
            logger.warning("Failed to parse pip-audit JSON: %s", e)
            logger.debug("Raw stdout: %s", stdout[:500])
            return []

        return self._parse_results(data, source)

    @staticmethod
    def _extract_error_hint(stderr: str) -> str:
        """Return the most informative line(s) from pip-audit stderr.

        For Python tracebacks the last non-blank line is usually the
        exception; for other output just return the last few lines.
        """
        lines = [l for l in stderr.splitlines() if l.strip()]
        if not lines:
            return stderr[:300]
        for line in reversed(lines):
            stripped = line.strip()
            if stripped and not stripped.startswith(("File ", "File \"", "Traceback")):
                return stripped[:300]
        return lines[-1].strip()[:300]

    @staticmethod
    def _is_resolution_failure(stderr: str) -> bool:
        """Heuristic: does stderr indicate a dependency-resolution problem?"""
        markers = (
            "ensurepip",
            "CalledProcessError",
            "ResolutionImpossible",
            "No matching distribution",
            "Could not find a version",
            "InstallationError",
            "BacktrackingResolver",
            "SIGABRT",
            "pip._vendor",
        )
        lower = stderr.lower()
        return any(m.lower() in lower for m in markers)

    def _parse_results(
        self, data: Dict[str, Any], source: str
    ) -> List[SecurityFinding]:
        """Convert pip-audit JSON output into SecurityFinding objects."""
        findings: List[SecurityFinding] = []
        dependencies = data.get("dependencies", [])

        total_packages = len(dependencies)
        vulnerable_packages = 0
        total_vulns = 0

        for dep in dependencies:
            name = dep.get("name", "unknown")
            version = dep.get("version", "unknown")
            vulns = dep.get("vulns", [])

            if not vulns:
                continue

            vulnerable_packages += 1

            for vuln in vulns:
                total_vulns += 1
                finding = self._create_finding(name, version, vuln, source)
                findings.append(finding)

        self.last_scan_summary = {
            "total_packages": total_packages,
            "vulnerable_packages": vulnerable_packages,
            "total_vulnerabilities": total_vulns,
            "clean_packages": total_packages - vulnerable_packages,
            "source": source,
        }

        logger.info(
            "vulnerable-packages scan summary: %d packages scanned, "
            "%d vulnerable (%d total vulnerabilities)",
            total_packages,
            vulnerable_packages,
            total_vulns,
        )

        return findings

    def _create_finding(
        self,
        package_name: str,
        version: str,
        vuln: Dict[str, Any],
        source: str,
    ) -> SecurityFinding:
        """Create a SecurityFinding for a single vulnerability."""
        vuln_id = vuln.get("id", "UNKNOWN")
        fix_versions = vuln.get("fix_versions", [])
        aliases = vuln.get("aliases", [])
        description = vuln.get("description", "")

        has_fix = len(fix_versions) > 0
        # Severity reflects remediation urgency, not CVSS score:
        # HIGH  = a fix is available → upgrade immediately
        # MEDIUM = no fix yet → monitor and mitigate
        severity = "HIGH" if has_fix else "MEDIUM"

        fix_str = ", ".join(fix_versions) if fix_versions else "No fix available"
        alias_str = ", ".join(aliases) if aliases else "None"

        summary_parts = [
            f"Vulnerable dependency: {package_name}=={version} [{vuln_id}]",
            f"Aliases: {alias_str}",
            f"Fix: {fix_str}",
        ]
        if description:
            summary_parts.append(f"Details: {description}")
        summary = " | ".join(summary_parts)

        threat_info = ThreatMapping.get_threat_mapping(
            "vulnerable_packages", "VULNERABLE_DEPENDENCY"
        )

        return SecurityFinding(
            severity=severity,
            summary=summary,
            analyzer="VULNERABLE_PACKAGES",
            threat_category=threat_info["scanner_category"],
            details={
                "package_name": package_name,
                "installed_version": version,
                "vulnerability_id": vuln_id,
                "fix_versions": fix_versions,
                "aliases": aliases,
                "description": description,
                "source": source,
                "threat_type": "VULNERABLE_DEPENDENCY",
                "confidence": 0.95,
                "references": [f"https://osv.dev/vulnerability/{vuln_id}"],
                "remediation": (
                    f"Upgrade {package_name} to version {fix_str}."
                    if has_fix
                    else f"Monitor {vuln_id} for a fix release and consider alternatives."
                ),
                "aitech": threat_info["aitech"],
                "aitech_name": threat_info["aitech_name"],
                "aisubtech": threat_info["aisubtech"],
                "aisubtech_name": threat_info["aisubtech_name"],
                "taxonomy_description": threat_info["description"],
            },
        )
