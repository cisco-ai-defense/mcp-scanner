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

"""``virustotal``: submit local files to VirusTotal for reputation lookup."""

import json
import os
import sys
from typing import Any, Optional

from mcpscanner.core.analyzers.virustotal_analyzer import VirusTotalAnalyzer
from mcpscanner.utils.logging_config import get_logger

from ..context import CommandContext
from ..results import analyzer_finding_payload

logger = get_logger(__name__)


async def run(ctx: CommandContext) -> Optional[Any]:
    """Look up a file or directory tree against VirusTotal."""
    args = ctx.args

    from mcpscanner.config.constants import MCPScannerConstants as CONSTANTS

    scan_path = args.scan_path

    vt_api_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
    if not vt_api_key:
        print(
            "Error: VIRUSTOTAL_API_KEY environment variable is not set.",
            file=sys.stderr,
        )
        sys.exit(1)

    vt_enabled_env = os.environ.get("MCP_SCANNER_VIRUSTOTAL_ENABLED", "true").lower()
    vt_enabled = vt_enabled_env != "false"
    vt_upload = (
        os.environ.get("MCP_SCANNER_VIRUSTOTAL_UPLOAD_FILES", "false").lower() == "true"
    )

    analyzer = VirusTotalAnalyzer(
        api_key=vt_api_key,
        enabled=vt_enabled,
        upload_files=vt_upload,
        max_files=CONSTANTS.VIRUSTOTAL_MAX_FILES,
        inclusion_extensions=CONSTANTS.VIRUSTOTAL_INCLUSION_EXTENSIONS,
        exclusion_extensions=CONSTANTS.VIRUSTOTAL_EXCLUSION_EXTENSIONS,
    )

    if os.path.isfile(scan_path):
        finding = analyzer.analyze_file(scan_path)
        findings = [finding] if finding else []
    elif os.path.isdir(scan_path):
        findings = analyzer.analyze_directory(scan_path)
    else:
        print(f"Error: Path does not exist: {scan_path}", file=sys.stderr)
        sys.exit(1)

    # Format results to match Scanner output structure
    results = []
    if findings:
        for finding in findings:
            file_path = (
                finding.details.get("file_path", scan_path)
                if finding.details
                else scan_path
            )
            analyzer_finding = analyzer_finding_payload(finding)

            results.append(
                {
                    "tool_name": file_path,
                    "tool_description": f"VirusTotal scan of {os.path.basename(file_path)}",
                    "status": "completed",
                    "is_safe": False,
                    "findings": {"virustotal_analyzer": analyzer_finding},
                }
            )
    else:
        results.append(
            {
                "tool_name": scan_path,
                "tool_description": f"VirusTotal scan of {os.path.basename(scan_path)}",
                "status": "completed",
                "is_safe": True,
                "findings": {
                    "virustotal_analyzer": {
                        "severity": "SAFE",
                        "threat_summary": "No threats detected",
                        "threat_names": [],
                        "total_findings": 0,
                        "mcp_taxonomies": [],
                    }
                },
            }
        )

    # Add scan summary if directory scan
    if os.path.isdir(scan_path) and analyzer.last_scan_summary:
        summary = analyzer.last_scan_summary
        logger.info(
            "VT scan summary: %d scanned, %d clean, %d malicious, %d not found",
            summary.get("scanned", 0),
            summary.get("clean", 0),
            summary.get("malicious", 0),
            summary.get("not_found", 0),
        )

    # Save output if requested
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        if args.verbose:
            print(f"Results saved to {args.output}")
    return results
