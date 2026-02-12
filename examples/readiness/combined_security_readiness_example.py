#!/usr/bin/env python3
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
Example script demonstrating combined security and readiness scanning.

This example shows how to run both security analyzers (YARA, LLM) and the
readiness analyzer together for comprehensive tool assessment.

Security scanning answers: "Is this tool safe?"
Readiness scanning answers: "Will this tool be reliable in production?"

Usage:
    python combined_security_readiness_example.py <server_url>

Example:
    python combined_security_readiness_example.py http://127.0.0.1:8000/mcp
"""

import asyncio
import os
import sys
from mcpscanner import Config, Scanner
from mcpscanner.core.models import AnalyzerEnum


async def main():
    # Check command line arguments
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <server_url>")
        sys.exit(1)

    server_url = sys.argv[1]

    # Determine available analyzers based on environment
    analyzers = [AnalyzerEnum.YARA, AnalyzerEnum.READINESS]

    # Add LLM analyzer if API key is available
    llm_api_key = os.environ.get("MCP_SCANNER_LLM_API_KEY")
    if llm_api_key:
        analyzers.append(AnalyzerEnum.LLM)
        print("LLM analyzer enabled")
    else:
        print("LLM analyzer disabled (no MCP_SCANNER_LLM_API_KEY)")

    # Add API analyzer if Cisco AI Defense key is available
    api_key = os.environ.get("MCP_SCANNER_API_KEY")
    if api_key:
        analyzers.append(AnalyzerEnum.API)
        print("API analyzer enabled")
    else:
        print("API analyzer disabled (no MCP_SCANNER_API_KEY)")

    print(f"\nActive analyzers: {[a.value for a in analyzers]}")
    print()

    # Create configuration
    config = Config(
        api_key=api_key,
        llm_provider_api_key=llm_api_key
    )

    # Create scanner
    scanner = Scanner(config)

    try:
        # Scan all tools with combined analyzers
        print(f"Scanning tools on {server_url}...")
        results = await scanner.scan_remote_server_tools(
            server_url,
            analyzers=analyzers
        )

        print(f"\nScan completed. Found {len(results)} tools.\n")

        for result in results:
            print(f"Tool: {result.tool_name}")
            print(f"  Overall Safe: {result.is_safe}")
            print(f"  Total Findings: {len(result.findings)}")

            # Separate findings by analyzer type
            security_findings = []
            readiness_findings = []

            for finding in result.findings:
                rule_id = finding.details.get("rule_id", "") if finding.details else ""
                if rule_id.startswith("HEUR-"):
                    readiness_findings.append(finding)
                else:
                    security_findings.append(finding)

            # Display security findings
            if security_findings:
                print(f"\n  Security Findings ({len(security_findings)}):")
                for finding in security_findings:
                    print(f"    [{finding.severity}] {finding.threat_category}: {finding.summary[:60]}...")

            # Display readiness findings
            if readiness_findings:
                # Get readiness score from first finding
                details = readiness_findings[0].details or {}
                score = details.get("readiness_score", "N/A")
                is_prod_ready = details.get("is_production_ready", "N/A")

                print(f"\n  Readiness Findings ({len(readiness_findings)}):")
                print(f"    Score: {score}/100, Production Ready: {is_prod_ready}")
                for finding in readiness_findings:
                    rule_id = finding.details.get("rule_id", "N/A") if finding.details else "N/A"
                    print(f"    [{finding.severity}] {rule_id}: {finding.summary[:60]}...")

            print()

        # Summary
        print("-" * 60)
        safe_count = sum(1 for r in results if r.is_safe)
        unsafe_count = len(results) - safe_count
        print(f"Summary: {safe_count} tools passed, {unsafe_count} tools have issues")

    except ValueError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")


if __name__ == "__main__":
    asyncio.run(main())

