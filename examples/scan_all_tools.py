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
Example script to scan all tools on an MCP server using the MCP Scanner SDK.

Usage:
    python scan_all_tools.py <server_url> <api_key>

Example:
    python scan_all_tools.py https://mcp-server.example.com your_api_key
"""

import asyncio
import sys
from mcpscanner import Config, Scanner


async def main():
    # Check command line arguments
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <server_url> <api_key>")
        sys.exit(1)

    server_url = sys.argv[1]
    api_key = sys.argv[2]

    # Create configuration
    config = Config(api_key=api_key)

    # Create scanner
    scanner = Scanner(config)

    try:
        # Scan all tools on the server
        print(f"Scanning all tools on server {server_url}...")
        results = await scanner.scan_remote_server_tools(server_url)

        # Print scan summary
        print(f"\nScan completed. Found {len(results)} tools.")

        # Count safe and vulnerable tools
        safe_tools = [r for r in results if r.is_safe]
        vulnerable_tools = [r for r in results if not r.is_safe]

        print(f"Safe tools: {len(safe_tools)}")
        print(f"Vulnerable tools: {len(vulnerable_tools)}")

        # Print details for vulnerable tools
        if vulnerable_tools:
            print("\nDetails for vulnerable tools:")
            for result in vulnerable_tools:
                print(f"\nTool: {result.tool_name}")
                print(f"Status: {result.status}")
                print(f"Vulnerabilities: {len(result.vulnerabilities)}")

                for i, vuln in enumerate(result.vulnerabilities, 1):
                    print(f"  Vulnerability #{i}:{vuln}")

    except ValueError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")


if __name__ == "__main__":
    asyncio.run(main())
