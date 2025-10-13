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

"""Test script to scan prompts from both stdio and HTTP MCP servers."""

import asyncio
import os
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from mcpscanner import Config, Scanner
from mcpscanner.core.models import AnalyzerEnum
from mcpscanner.core.mcp_models import StdioServer


def print_separator(title=""):
    """Print a separator line."""
    if title:
        print(f"\n{'=' * 70}")
        print(f"  {title}")
        print('=' * 70)
    else:
        print('=' * 70)


def print_result(result, index=None):
    """Print a single prompt scan result."""
    prefix = f"[{index}] " if index is not None else ""
    status_icon = "✅" if result.is_safe else "⚠️"

    print(f"\n{prefix}{status_icon} Prompt: {result.prompt_name}")
    print(f"   Description: {result.prompt_description[:80]}...")
    print(f"   Status: {result.status}")
    print(f"   Analyzers: {', '.join(result.analyzers)}")
    print(f"   Safe: {result.is_safe}")

    if not result.is_safe:
        print(f"   ⚠️  Findings ({len(result.findings)}):")
        for finding in result.findings:
            print(f"      [{finding.analyzer}] {finding.severity}: {finding.summary}")
            if finding.details:
                threat_type = finding.details.get('threat_type', 'Unknown')
                print(f"         Threat Type: {threat_type}")


async def test_stdio_server():
    """Test scanning prompts from stdio server."""
    print_separator("TEST 1: Stdio MCP Server with Prompts")

    # Configure scanner
    config = Config(
        api_key=os.getenv("MCP_SCANNER_API_KEY"),
        llm_provider_api_key=os.getenv("MCP_SCANNER_LLM_API_KEY"),
        llm_model=os.getenv("MCP_SCANNER_LLM_MODEL", "azure/gpt-4.1"),
        llm_base_url=os.getenv("MCP_SCANNER_LLM_BASE_URL"),
        llm_api_version=os.getenv("MCP_SCANNER_LLM_API_VERSION"),
    )

    scanner = Scanner(config)

    # Configure stdio server
    server_config = StdioServer(
        command="python3",
        args=[str(Path(__file__).parent / "stdio_prompt_server.py")]
    )

    print(f"\nServer Command: {server_config.command} {' '.join(server_config.args)}")

    # Determine available analyzers
    analyzers = []
    if scanner._api_analyzer:
        analyzers.append(AnalyzerEnum.API)
        print("✓ API Analyzer enabled")
    if scanner._llm_analyzer:
        analyzers.append(AnalyzerEnum.LLM)
        print("✓ LLM Analyzer enabled")
    if scanner._yara_analyzer:
        analyzers.append(AnalyzerEnum.YARA)
        print("✓ YARA Analyzer enabled")

    if not analyzers:
        print("⚠️  No analyzers available. Configure API keys.")
        return

    print(f"\nScanning with: {', '.join([a.value for a in analyzers])}")
    print("\nConnecting to stdio server...")

    try:
        # Scan all prompts
        results = await scanner.scan_stdio_server_prompts(
            server_config,
            analyzers=analyzers,
            timeout=30
        )

        print(f"\n✅ Successfully scanned {len(results)} prompts")

        # Display results
        safe_count = sum(1 for r in results if r.is_safe)
        unsafe_count = len(results) - safe_count

        print(f"\nSummary:")
        print(f"  Total prompts: {len(results)}")
        print(f"  Safe: {safe_count}")
        print(f"  Unsafe: {unsafe_count}")

        print("\nDetailed Results:")
        for i, result in enumerate(results, 1):
            print_result(result, i)

        return results

    except Exception as e:
        print(f"\n❌ Error scanning stdio server: {e}")
        import traceback
        traceback.print_exc()
        return None


async def test_http_server():
    """Test scanning prompts from HTTP server."""
    print_separator("TEST 2: Streamable HTTP MCP Server with Prompts")

    # Configure scanner
    config = Config(
        api_key=os.getenv("MCP_SCANNER_API_KEY"),
        llm_provider_api_key=os.getenv("MCP_SCANNER_LLM_API_KEY"),
        llm_model=os.getenv("MCP_SCANNER_LLM_MODEL", "azure/gpt-4.1"),
        llm_base_url=os.getenv("MCP_SCANNER_LLM_BASE_URL"),
        llm_api_version=os.getenv("MCP_SCANNER_LLM_API_VERSION"),
    )

    scanner = Scanner(config)

    server_url = "http://127.0.0.1:8000"

    print(f"\nServer URL: {server_url}")

    # Determine available analyzers
    analyzers = []
    if scanner._api_analyzer:
        analyzers.append(AnalyzerEnum.API)
        print("✓ API Analyzer enabled")
    if scanner._llm_analyzer:
        analyzers.append(AnalyzerEnum.LLM)
        print("✓ LLM Analyzer enabled")
    if scanner._yara_analyzer:
        analyzers.append(AnalyzerEnum.YARA)
        print("✓ YARA Analyzer enabled")

    if not analyzers:
        print("⚠️  No analyzers available. Configure API keys.")
        return

    print(f"\nScanning with: {', '.join([a.value for a in analyzers])}")
    print("\nConnecting to HTTP server...")

    try:
        # Scan all prompts
        results = await scanner.scan_remote_server_prompts(
            server_url,
            analyzers=analyzers
        )

        print(f"\n✅ Successfully scanned {len(results)} prompts")

        # Display results
        safe_count = sum(1 for r in results if r.is_safe)
        unsafe_count = len(results) - safe_count

        print(f"\nSummary:")
        print(f"  Total prompts: {len(results)}")
        print(f"  Safe: {safe_count}")
        print(f"  Unsafe: {unsafe_count}")

        print("\nDetailed Results:")
        for i, result in enumerate(results, 1):
            print_result(result, i)

        return results

    except Exception as e:
        print(f"\n❌ Error scanning HTTP server: {e}")
        import traceback
        traceback.print_exc()
        return None


async def test_specific_prompt():
    """Test scanning a specific prompt by name."""
    print_separator("TEST 3: Scan Specific Prompt")

    config = Config(
        llm_provider_api_key=os.getenv("MCP_SCANNER_LLM_API_KEY"),
        llm_model=os.getenv("MCP_SCANNER_LLM_MODEL", "azure/gpt-4.1"),
        llm_base_url=os.getenv("MCP_SCANNER_LLM_BASE_URL"),
        llm_api_version=os.getenv("MCP_SCANNER_LLM_API_VERSION"),
    )

    scanner = Scanner(config)
    server_url = "http://127.0.0.1:8000"
    prompt_name = "execute_system_command"

    print(f"\nScanning specific prompt: '{prompt_name}'")
    print(f"Server: {server_url}")

    try:
        result = await scanner.scan_remote_server_prompt(
            server_url,
            prompt_name,
            analyzers=[AnalyzerEnum.LLM]
        )

        print("\n✅ Scan completed")
        print_result(result)

        return result

    except Exception as e:
        print(f"\n❌ Error: {e}")
        return None


async def main():
    """Run all tests."""
    print("\n" + "=" * 70)
    print("  MCP Prompt Server Testing Suite")
    print("=" * 70)

    # Check configuration
    has_api = bool(os.getenv("MCP_SCANNER_API_KEY"))
    has_llm = bool(os.getenv("MCP_SCANNER_LLM_API_KEY"))

    print("\nConfiguration:")
    print(f"  API Key: {'✓' if has_api else '✗'}")
    print(f"  LLM Key: {'✓' if has_llm else '✗'}")

    if os.getenv("MCP_SCANNER_LLM_BASE_URL"):
        print(f"  LLM URL: {os.getenv('MCP_SCANNER_LLM_BASE_URL')}")
    if os.getenv("MCP_SCANNER_LLM_MODEL"):
        print(f"  LLM Model: {os.getenv('MCP_SCANNER_LLM_MODEL')}")

    if not has_api and not has_llm:
        print("\n⚠️  Warning: No API keys configured. Only YARA analysis will be available.")

    # Test 1: Stdio server
    stdio_results = await test_stdio_server()

    # Test 2: HTTP server (requires server to be running)
    print("\n\n⚠️  NOTE: HTTP server test requires the server to be running.")
    print("Start the server in another terminal with:")
    print("  python3 test_servers/http_prompt_server.py")

    response = input("\nIs the HTTP server running? (y/n): ").strip().lower()

    if response == 'y':
        http_results = await test_http_server()

        # Test 3: Specific prompt
        if http_results:
            await asyncio.sleep(1)
            await test_specific_prompt()
    else:
        print("\nSkipping HTTP server tests.")

    # Final summary
    print_separator("FINAL SUMMARY")

    if stdio_results:
        print(f"\n✅ Stdio Server: Scanned {len(stdio_results)} prompts")
        unsafe = [r for r in stdio_results if not r.is_safe]
        if unsafe:
            print(f"   ⚠️  {len(unsafe)} unsafe prompts detected:")
            for r in unsafe:
                print(f"      - {r.prompt_name}")

    print("\n" + "=" * 70)
    print("Testing complete!")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(main())
