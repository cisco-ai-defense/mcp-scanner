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

"""Complete test: Scan both prompts and resources from HTTP MCP server.

Run the HTTP server first:
    python3 examples/prompts/http_prompt_server.py

Then run this test:
    python3 examples/test_complete.py
"""

import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from mcpscanner import Config, Scanner
from mcpscanner.core.models import AnalyzerEnum


async def main():
    print("=" * 70)
    print("COMPLETE TEST: Prompts + Resources Scanning")
    print("=" * 70)

    config = Config(
        llm_provider_api_key=os.getenv("MCP_SCANNER_LLM_API_KEY"),
        llm_model=os.getenv("MCP_SCANNER_LLM_MODEL", "azure/gpt-4.1"),
        llm_base_url=os.getenv("MCP_SCANNER_LLM_BASE_URL"),
        llm_api_version=os.getenv("MCP_SCANNER_LLM_API_VERSION"),
    )

    scanner = Scanner(config)
    server_url = "http://127.0.0.1:8000/mcp"

    print(f"\nServer: {server_url}")
    print(f"LLM Model: {config.llm_model}")
    print()

    # Test 1: Scan Prompts
    print("=" * 70)
    print("TEST 1: Scanning Prompts")
    print("=" * 70)

    try:
        prompt_results = await scanner.scan_remote_server_prompts(
            server_url,
            analyzers=[AnalyzerEnum.LLM]
        )

        print(f"\n✅ Scanned {len(prompt_results)} prompts\n")

        for result in prompt_results:
            status = "✅ SAFE" if result.is_safe else "⚠️  UNSAFE"
            print(f"{status} {result.prompt_name}")
            print(f"   {result.prompt_description[:60]}...")

            if not result.is_safe:
                for finding in result.findings:
                    threats = finding.details.get('threat_type', 'Unknown') if finding.details else 'Unknown'
                    print(f"   [{finding.analyzer}] {finding.severity}: {threats}")
            print()

        # Prompt Summary
        safe_prompts = sum(1 for r in prompt_results if r.is_safe)
        unsafe_prompts = len(prompt_results) - safe_prompts
        print(f"Prompt Summary: {safe_prompts} safe, {unsafe_prompts} unsafe\n")

    except Exception as e:
        print(f"❌ Error scanning prompts: {e}\n")
        prompt_results = []

    # Test 2: Scan Resources
    print("=" * 70)
    print("TEST 2: Scanning Resources")
    print("=" * 70)

    try:
        resource_results = await scanner.scan_remote_server_resources(
            server_url,
            analyzers=[AnalyzerEnum.LLM],
            allowed_mime_types=["text/plain", "text/html"]
        )

        print(f"\n✅ Scanned {len(resource_results)} resources\n")

        for result in resource_results:
            if result.status == "skipped":
                print(f"⏭️  SKIPPED {result.resource_name}")
                print(f"   URI: {result.resource_uri}")
                print(f"   MIME: {result.resource_mime_type}")
            elif result.status == "completed":
                status = "✅ SAFE" if result.is_safe else "⚠️  UNSAFE"
                print(f"{status} {result.resource_name}")
                print(f"   URI: {result.resource_uri}")
                print(f"   MIME: {result.resource_mime_type}")

                if not result.is_safe:
                    for finding in result.findings:
                        threats = finding.details.get('threat_type', 'Unknown') if finding.details else 'Unknown'
                        print(f"   [{finding.analyzer}] {finding.severity}: {threats}")
            print()

        # Resource Summary
        completed = [r for r in resource_results if r.status == "completed"]
        skipped = [r for r in resource_results if r.status == "skipped"]
        safe_resources = sum(1 for r in completed if r.is_safe)
        unsafe_resources = len(completed) - safe_resources

        print(f"Resource Summary: {safe_resources} safe, {unsafe_resources} unsafe, {len(skipped)} skipped\n")

    except Exception as e:
        print(f"❌ Error scanning resources: {e}\n")
        resource_results = []

    # Final Summary
    print("=" * 70)
    print("FINAL SUMMARY")
    print("=" * 70)

    if prompt_results:
        safe_prompts = sum(1 for r in prompt_results if r.is_safe)
        unsafe_prompts = len(prompt_results) - safe_prompts
        print(f"\nPrompts:")
        print(f"  Total: {len(prompt_results)}")
        print(f"  ✅ Safe: {safe_prompts}")
        print(f"  ⚠️  Unsafe: {unsafe_prompts}")

    if resource_results:
        completed = [r for r in resource_results if r.status == "completed"]
        skipped = [r for r in resource_results if r.status == "skipped"]
        safe_resources = sum(1 for r in completed if r.is_safe)
        unsafe_resources = len(completed) - safe_resources

        print(f"\nResources:")
        print(f"  Total: {len(resource_results)}")
        print(f"  ✅ Safe: {safe_resources}")
        print(f"  ⚠️  Unsafe: {unsafe_resources}")
        print(f"  ⏭️  Skipped: {len(skipped)}")

    total_scanned = len(prompt_results) + len([r for r in resource_results if r.status == "completed"])
    total_safe = (sum(1 for r in prompt_results if r.is_safe) +
                  sum(1 for r in resource_results if r.status == "completed" and r.is_safe))
    total_unsafe = total_scanned - total_safe

    print(f"\nOverall:")
    print(f"  Total Scanned: {total_scanned}")
    print(f"  ✅ Safe: {total_safe}")
    print(f"  ⚠️  Unsafe: {total_unsafe}")

    print("\n" + "=" * 70)
    print("✅ Complete test finished successfully!")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(main())
