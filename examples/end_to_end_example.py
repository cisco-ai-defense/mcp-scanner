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
End-to-end test for MCP Scanner - Tools, Prompts, and Resources
This script tests the complete scanning functionality.
"""

import asyncio
import sys
from mcpscanner import Config, Scanner
from mcpscanner.core.models import AnalyzerEnum

async def test_tool_scanning():
    """Test tool scanning functionality."""
    print("\n" + "="*80)
    print("TEST 1: Tool Scanning")
    print("="*80)

    try:
        # Create scanner with YARA only (no API key needed)
        config = Config()
        scanner = Scanner(config)

        # Test with a simple HTTP server (you'll need to start examples/prompts/http_prompt_server.py)
        server_url = "http://127.0.0.1:8000/mcp"

        print(f"\n📡 Scanning tools on: {server_url}")
        print(f"🔍 Using analyzers: YARA")

        results = await scanner.scan_remote_server_tools(
            server_url,
            analyzers=[AnalyzerEnum.YARA]
        )

        print(f"\n✅ Tool scan completed!")
        print(f"📊 Total tools scanned: {len(results)}")

        for result in results:
            status_icon = "✅" if result.is_safe else "⚠️"
            print(f"  {status_icon} {result.tool_name}: {result.status} - Safe: {result.is_safe}")
            if not result.is_safe:
                print(f"     Findings: {len(result.findings)}")

        return True

    except Exception as e:
        print(f"\n❌ Tool scanning failed: {e}")
        return False

async def test_prompt_scanning():
    """Test prompt scanning functionality."""
    print("\n" + "="*80)
    print("TEST 2: Prompt Scanning")
    print("="*80)

    try:
        # Create scanner with YARA only
        config = Config()
        scanner = Scanner(config)

        server_url = "http://127.0.0.1:8000/mcp"

        print(f"\n📡 Scanning prompts on: {server_url}")
        print(f"🔍 Using analyzers: YARA")

        results = await scanner.scan_remote_server_prompts(
            server_url,
            analyzers=[AnalyzerEnum.YARA]
        )

        print(f"\n✅ Prompt scan completed!")
        print(f"📊 Total prompts scanned: {len(results)}")

        for result in results:
            status_icon = "✅" if result.is_safe else "⚠️"
            print(f"  {status_icon} {result.prompt_name}: {result.status} - Safe: {result.is_safe}")
            print(f"     Description: {result.prompt_description[:60]}...")
            if not result.is_safe:
                print(f"     Findings: {len(result.findings)}")

        return True

    except Exception as e:
        print(f"\n❌ Prompt scanning failed: {e}")
        return False

async def test_resource_scanning():
    """Test resource scanning functionality."""
    print("\n" + "="*80)
    print("TEST 3: Resource Scanning")
    print("="*80)

    try:
        # Create scanner with YARA only
        config = Config()
        scanner = Scanner(config)

        server_url = "http://127.0.0.1:8000/mcp"

        print(f"\n📡 Scanning resources on: {server_url}")
        print(f"🔍 Using analyzers: YARA")
        print(f"📄 MIME types: text/plain, text/html")

        results = await scanner.scan_remote_server_resources(
            server_url,
            analyzers=[AnalyzerEnum.YARA],
            allowed_mime_types=["text/plain", "text/html", "application/json"]
        )

        print(f"\n✅ Resource scan completed!")
        print(f"📊 Total resources: {len(results)}")

        scanned = [r for r in results if r.status == "completed"]
        skipped = [r for r in results if r.status == "skipped"]

        print(f"   Scanned: {len(scanned)}")
        print(f"   Skipped: {len(skipped)}")

        for result in results:
            if result.status == "completed":
                status_icon = "✅" if result.is_safe else "⚠️"
                print(f"  {status_icon} {result.resource_name} ({result.resource_mime_type})")
                print(f"     URI: {result.resource_uri}")
                print(f"     Safe: {result.is_safe}")
                if not result.is_safe:
                    print(f"     Findings: {len(result.findings)}")
            elif result.status == "skipped":
                print(f"  ⏭️  {result.resource_name} ({result.resource_mime_type}) - SKIPPED")

        return True

    except Exception as e:
        print(f"\n❌ Resource scanning failed: {e}")
        return False

async def test_specific_items():
    """Test scanning specific items."""
    print("\n" + "="*80)
    print("TEST 4: Scanning Specific Items")
    print("="*80)

    try:
        config = Config()
        scanner = Scanner(config)
        server_url = "http://127.0.0.1:8000/mcp"

        # Test specific tool
        print("\n🔧 Scanning specific tool: 'add'")
        try:
            tool_result = await scanner.scan_remote_server_tool(
                server_url,
                "add",
                analyzers=[AnalyzerEnum.YARA]
            )
            print(f"  ✅ Tool 'add': {tool_result.status} - Safe: {tool_result.is_safe}")
        except ValueError as e:
            print(f"  ℹ️  Tool 'add' not found (expected if server doesn't have it)")

        # Test specific prompt
        print("\n💬 Scanning specific prompt: 'greet_user'")
        try:
            prompt_result = await scanner.scan_remote_server_prompt(
                server_url,
                "greet_user",
                analyzers=[AnalyzerEnum.YARA]
            )
            print(f"  ✅ Prompt 'greet_user': {prompt_result.status} - Safe: {prompt_result.is_safe}")
        except ValueError as e:
            print(f"  ℹ️  Prompt 'greet_user' not found (expected if server doesn't have it)")

        # Test specific resource
        print("\n📄 Scanning specific resource: 'file://test/document.txt'")
        try:
            resource_result = await scanner.scan_remote_server_resource(
                server_url,
                "file://test/document.txt",
                analyzers=[AnalyzerEnum.YARA],
                allowed_mime_types=["text/plain"]
            )
            print(f"  ✅ Resource: {resource_result.status} - Safe: {resource_result.is_safe}")
        except ValueError as e:
            print(f"  ℹ️  Resource not found (expected if server doesn't have it)")

        return True

    except Exception as e:
        print(f"\n❌ Specific item scanning failed: {e}")
        return False

async def main():
    """Run all end-to-end tests."""
    print("\n" + "="*80)
    print("🚀 MCP SCANNER - END-TO-END TEST SUITE")
    print("="*80)
    print("\n⚠️  Prerequisites:")
    print("   1. Start the test HTTP server:")
    print("      python examples/prompts/http_prompt_server.py")
    print("   2. Server should be running on http://127.0.0.1:8000/mcp")
    print("\n" + "="*80)

    input("\nPress Enter to start tests (or Ctrl+C to cancel)...")

    results = []

    # Run all tests
    results.append(("Tool Scanning", await test_tool_scanning()))
    results.append(("Prompt Scanning", await test_prompt_scanning()))
    results.append(("Resource Scanning", await test_resource_scanning()))
    results.append(("Specific Items", await test_specific_items()))

    # Summary
    print("\n" + "="*80)
    print("📊 TEST SUMMARY")
    print("="*80)

    passed = sum(1 for _, result in results if result)
    total = len(results)

    for test_name, result in results:
        status = "✅ PASSED" if result else "❌ FAILED"
        print(f"  {status}: {test_name}")

    print(f"\n🎯 Results: {passed}/{total} tests passed")

    if passed == total:
        print("\n🎉 All tests passed successfully!")
        return 0
    else:
        print(f"\n⚠️  {total - passed} test(s) failed")
        return 1

if __name__ == "__main__":
    try:
        exit_code = asyncio.run(main())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n\n⚠️  Tests cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
