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

"""``vulnerable-package``: match installed dependencies against advisories."""

import json
import os
import sys
from typing import Any, Optional

from mcpscanner.core.models import AnalyzerEnum
from mcpscanner.utils.logging_config import get_logger

from ..context import CommandContext
from ..results import analyzer_finding_payload

logger = get_logger(__name__)


async def run(ctx: CommandContext) -> Optional[Any]:
    """Resolve the dependency set under a path and look for known CVEs."""
    args = ctx.args

    from mcpscanner.core.analyzers.vulnerable_package_analyzer import VulnerablePackageAnalyzer
    from mcpscanner.config.constants import MCPScannerConstants as CONSTANTS

    scan_path = args.scan_path

    if not os.path.exists(scan_path):
        print(f"Error: Path does not exist: {scan_path}", file=sys.stderr)
        sys.exit(1)

    vuln_service = (
        args.vulnerability_service
        or CONSTANTS.VULNERABLE_PACKAGE_VULNERABILITY_SERVICE
    )

    analyzer = VulnerablePackageAnalyzer(
        enabled=True,
        vulnerability_service=vuln_service,
        timeout=CONSTANTS.VULNERABLE_PACKAGE_TIMEOUT,
        fix_mode=getattr(args, "fix", False),
        skip_deps=getattr(args, "no_deps", False),
        disable_pip=getattr(args, "disable_pip", False),
    )

    findings = analyzer.analyze_path(scan_path)

    results = []
    if findings:
        for finding in findings:
            pkg = finding.details.get("package_name", "unknown") if finding.details else "unknown"
            ver = finding.details.get("installed_version", "?") if finding.details else "?"
            vuln_id = finding.details.get("vulnerability_id", "") if finding.details else ""

            analyzer_finding = analyzer_finding_payload(finding)

            aliases = finding.details.get("aliases", []) if finding.details else []
            desc = finding.details.get("description", "") if finding.details else ""
            alias_str = ", ".join(aliases) if aliases else ""

            tool_desc_parts = [f"{vuln_id}: {pkg}=={ver}"]
            if alias_str:
                tool_desc_parts.append(f"Aliases: {alias_str}")
            if desc:
                tool_desc_parts.append(desc)

            results.append({
                "package_name": f"{pkg}=={ver}",
                "vulnerability_description": " | ".join(tool_desc_parts),
                "status": "completed",
                "is_safe": False,
                "findings": {"vulnerable_package_analyzer": analyzer_finding},
            })
    else:
        results.append({
            "package_name": scan_path,
            "vulnerability_description": f"Vulnerable package scan of {os.path.basename(scan_path)}",
            "status": "completed",
            "is_safe": True,
            "findings": {
                "vulnerable_package_analyzer": {
                    "severity": "SAFE",
                    "threat_summary": "No known vulnerabilities found",
                    "threat_names": [],
                    "total_findings": 0,
                    "mcp_taxonomies": [],
                }
            },
        })

    if analyzer.last_scan_summary:
        summary = analyzer.last_scan_summary
        logger.info(
            "vulnerable-package summary: %d packages, %d vulnerable (%d total vulns)",
            summary.get("total_packages", 0),
            summary.get("vulnerable_packages", 0),
            summary.get("total_vulnerabilities", 0),
        )

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        if args.verbose:
            print(f"Results saved to {args.output}")

    ctx.analyzers = [AnalyzerEnum.VULNERABLE_PACKAGE]
    return results
