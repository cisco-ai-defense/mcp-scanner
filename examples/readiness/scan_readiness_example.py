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
Example script to scan MCP tools for production readiness issues.

The Readiness Analyzer requires no API keys and performs zero-dependency
static analysis of tool definitions using 20 heuristic rules.

Usage:
    python scan_readiness_example.py <server_url>

Example:
    python scan_readiness_example.py http://127.0.0.1:8000/mcp
"""

import asyncio
import sys
from mcpscanner import Config, Scanner
from mcpscanner.core.models import AnalyzerEnum


async def main():
    # Check command line arguments
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <server_url>")
        sys.exit(1)

    server_url = sys.argv[1]

    # Create configuration - no API keys required for readiness scanning
    config = Config()

    # Create scanner
    scanner = Scanner(config)

    try:
        # Scan all tools using only the readiness analyzer
        print(f"Scanning tools for readiness issues on {server_url}...")
        results = await scanner.scan_remote_server_tools(
            server_url,
            analyzers=[AnalyzerEnum.READINESS]
        )

        # Print scan summary
        print(f"\nScan completed. Found {len(results)} tools.\n")

        for result in results:
            print(f"Tool: {result.tool_name}")
            print(f"  Status: {result.status}")
            print(f"  Safe: {result.is_safe}")
            print(f"  Findings: {len(result.findings)}")

            if result.findings:
                # Extract readiness score from first finding
                first_finding = result.findings[0]
                details = first_finding.details or {}
                score = details.get("readiness_score", "N/A")
                is_prod_ready = details.get("is_production_ready", "N/A")

                print(f"  Readiness Score: {score}")
                print(f"  Production Ready: {is_prod_ready}")

                print("  Issues:")
                for finding in result.findings:
                    rule_id = finding.details.get("rule_id", "N/A") if finding.details else "N/A"
                    print(f"    [{finding.severity}] {rule_id}: {finding.summary[:80]}...")

            print()

        # Summary statistics
        safe_tools = [r for r in results if r.is_safe]
        unsafe_tools = [r for r in results if not r.is_safe]

        print("-" * 60)
        print(f"Summary: {len(safe_tools)} production-ready, {len(unsafe_tools)} need attention")

    except ValueError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")


if __name__ == "__main__":
    asyncio.run(main())

