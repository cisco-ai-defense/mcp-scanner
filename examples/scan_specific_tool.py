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
Example script to scan a specific tool on an MCP server using the MCP Scanner SDK.

Usage:
    python scan_specific_tool.py <server_url> <tool_name> <api_key>

Example:
    python scan_specific_tool.py https://mcp-server.example.com tool_name your_api_key
"""

import asyncio
import sys
from mcpscanner import Config, Scanner


async def main():
    # Check command line arguments
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <server_url> <tool_name> <api_key>")
        sys.exit(1)

    server_url = sys.argv[1]
    tool_name = sys.argv[2]
    api_key = sys.argv[3]

    # Create configuration
    config = Config(api_key=api_key)

    # Create scanner
    scanner = Scanner(config)

    try:
        # Scan the specified tool
        print(f"Scanning tool '{tool_name}' on server {server_url}...")
        result = await scanner.scan_remote_server_tool(server_url, tool_name)

        # Print scan results
        print(f"\nScan Results for {result.tool_name}:")
        print(f"Status: {result.status}")
        print(f"Is Safe: {result.is_safe}")

        if result.vulnerabilities:
            print(f"\nFound {len(result.vulnerabilities)} vulnerabilities:")
            for i, vuln in enumerate(result.vulnerabilities, 1):
                print(f"\nVulnerability #{i}:")
                print(f"  Severity: {vuln.severity}")
                print(f"  Summary: {vuln.summary}")
                print(f"  Analyzer: {vuln.analyzer}")
        else:
            print("\nNo vulnerabilities found. Tool appears to be safe.")

    except ValueError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")


if __name__ == "__main__":
    asyncio.run(main())
