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

"""Example script demonstrating prompt scanning functionality.

This example shows how to:
1. List all prompts from an MCP server
2. Scan all prompts with both LLM and API analyzers
3. Scan a specific prompt by name
"""

import asyncio
import os
from mcpscanner import Config, Scanner
from mcpscanner.core.models import AnalyzerEnum


async def scan_remote_server_prompts_example():
    """Example: Scan all prompts from a remote MCP server."""

    # Configure the scanner with API keys
    config = Config(
        api_key=os.getenv("MCP_SCANNER_API_KEY"),
        llm_provider_api_key=os.getenv("MCP_SCANNER_LLM_API_KEY"),
        llm_model=os.getenv("MCP_SCANNER_LLM_MODEL", "gpt-4o"),
        llm_base_url=os.getenv("MCP_SCANNER_LLM_BASE_URL"),
    )

    scanner = Scanner(config)

    # Example server URL - replace with your MCP server
    server_url = "https://mcp.example.com/sse"

    print(f"Scanning prompts from: {server_url}\n")

    try:
        # Scan all prompts with both API and LLM analyzers
        results = await scanner.scan_remote_server_prompts(
            server_url,
            analyzers=[AnalyzerEnum.API, AnalyzerEnum.LLM]
        )

        print(f"Found {len(results)} prompts\n")

        # Display results
        for result in results:
            print(f"Prompt: {result.prompt_name}")
            print(f"  Description: {result.prompt_description}")
            print(f"  Status: {result.status}")
            print(f"  Safe: {result.is_safe}")
            print(f"  Analyzers used: {', '.join(result.analyzers)}")

            if not result.is_safe:
                print(f"  ⚠️  Found {len(result.findings)} security findings:")
                for finding in result.findings:
                    print(f"    - [{finding.severity}] {finding.summary} (Analyzer: {finding.analyzer})")
            else:
                print("  ✅ No security issues detected")
            print()

    except Exception as e:
        print(f"Error scanning prompts: {e}")


async def scan_specific_prompt_example():
    """Example: Scan a specific prompt by name."""

    config = Config(
        api_key=os.getenv("MCP_SCANNER_API_KEY"),
        llm_provider_api_key=os.getenv("MCP_SCANNER_LLM_API_KEY"),
    )

    scanner = Scanner(config)

    server_url = "https://mcp.example.com/sse"
    prompt_name = "example_prompt"

    print(f"Scanning specific prompt '{prompt_name}' from: {server_url}\n")

    try:
        # Scan a specific prompt
        result = await scanner.scan_remote_server_prompt(
            server_url,
            prompt_name,
            analyzers=[AnalyzerEnum.API, AnalyzerEnum.LLM]
        )

        print(f"Prompt: {result.prompt_name}")
        print(f"Description: {result.prompt_description}")
        print(f"Safe: {result.is_safe}")

        if not result.is_safe:
            print(f"\n⚠️  Security Findings ({len(result.findings)}):")
            for finding in result.findings:
                print(f"  [{finding.severity}] {finding.summary}")
                print(f"  Analyzer: {finding.analyzer}")
                if finding.details:
                    print(f"  Details: {finding.details}")
                print()
        else:
            print("\n✅ No security issues detected")

    except ValueError as e:
        print(f"Prompt not found: {e}")
    except Exception as e:
        print(f"Error scanning prompt: {e}")


async def scan_stdio_server_prompts_example():
    """Example: Scan prompts from a stdio MCP server."""

    from mcpscanner.core.mcp_models import StdioServer

    config = Config(
        api_key=os.getenv("MCP_SCANNER_API_KEY"),
        llm_provider_api_key=os.getenv("MCP_SCANNER_LLM_API_KEY"),
    )

    scanner = Scanner(config)

    # Example stdio server configuration
    server_config = StdioServer(
        command="uvx",
        args=["--from", "mcp-server-fetch", "mcp-server-fetch"]
    )

    print(f"Scanning prompts from stdio server: {server_config.command} {' '.join(server_config.args)}\n")

    try:
        # Scan all prompts from stdio server
        results = await scanner.scan_stdio_server_prompts(
            server_config,
            analyzers=[AnalyzerEnum.API, AnalyzerEnum.LLM],
            timeout=60
        )

        print(f"Found {len(results)} prompts\n")

        for result in results:
            status_icon = "✅" if result.is_safe else "⚠️"
            print(f"{status_icon} {result.prompt_name}: {result.prompt_description[:50]}...")
            if not result.is_safe:
                print(f"   Found {len(result.findings)} security findings")
            print()

    except Exception as e:
        print(f"Error scanning stdio server prompts: {e}")


async def list_prompts_only():
    """Example: Just list available prompts without scanning."""

    from mcp.client.session import ClientSession
    from mcp.client.sse import sse_client

    server_url = "https://mcp.example.com/sse"

    print(f"Listing prompts from: {server_url}\n")

    try:
        # Connect to server
        async with sse_client(server_url) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()

                # List all prompts
                prompts = await session.list_prompts()

                print(f"Available prompts ({len(prompts.prompts)}):")
                for prompt in prompts.prompts:
                    print(f"  - {prompt.name}")
                    if prompt.description:
                        print(f"    Description: {prompt.description}")
                    if prompt.arguments:
                        print(f"    Arguments: {len(prompt.arguments)}")
                    print()

    except Exception as e:
        print(f"Error listing prompts: {e}")


def main():
    """Run examples."""
    print("=" * 60)
    print("MCP Scanner - Prompt Scanning Examples")
    print("=" * 60)
    print()

    # Check for required environment variables
    if not os.getenv("MCP_SCANNER_API_KEY") and not os.getenv("MCP_SCANNER_LLM_API_KEY"):
        print("⚠️  Warning: No API keys configured")
        print("Set MCP_SCANNER_API_KEY and/or MCP_SCANNER_LLM_API_KEY")
        print()

    # Run examples (uncomment the one you want to test)

    # Example 1: Scan all prompts from remote server
    # asyncio.run(scan_remote_server_prompts_example())

    # Example 2: Scan a specific prompt
    # asyncio.run(scan_specific_prompt_example())

    # Example 3: Scan prompts from stdio server
    # asyncio.run(scan_stdio_server_prompts_example())

    # Example 4: Just list prompts without scanning
    # asyncio.run(list_prompts_only())

    print("\nTo run an example, uncomment the desired asyncio.run() call in main()")
    print("and update the server URL/configuration as needed.")


if __name__ == "__main__":
    main()
