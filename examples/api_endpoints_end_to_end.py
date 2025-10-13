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

"""Test the new prompt and resource API endpoints.

Make sure to start the API server first:
    uvicorn mcpscanner.api.api:app --reload

And the HTTP test server:
    python3 examples/prompts/http_prompt_server.py
"""

import asyncio
import httpx
import json


BASE_URL = "http://127.0.0.1:8080"
MCP_SERVER_URL = "http://127.0.0.1:8000/mcp"


async def test_scan_prompt():
    """Test scanning a specific prompt."""
    print("=" * 70)
    print("TEST 1: Scan Specific Prompt")
    print("=" * 70)

    payload = {
        "server_url": MCP_SERVER_URL,
        "tool_name": "execute_system_command",  # Using tool_name field for prompt_name
        "analyzers": ["llm"],
        "output_format": "raw",
    }

    async with httpx.AsyncClient(timeout=60.0) as client:
        response = await client.post(f"{BASE_URL}/scan-prompt", json=payload)

        if response.status_code == 200:
            result = response.json()
            print(f"\n✅ Prompt: {result['prompt_name']}")
            print(f"   Description: {result['prompt_description'][:60]}...")
            print(f"   Status: {result['status']}")
            print(f"   Safe: {result['is_safe']}")
            print(f"\n   Findings:")
            for analyzer, data in result['findings'].items():
                print(f"      {analyzer}: {data['severity']} - {data['threat_summary']}")
        else:
            print(f"❌ Error: {response.status_code}")
            print(response.text)
    print()


async def test_scan_all_prompts():
    """Test scanning all prompts."""
    print("=" * 70)
    print("TEST 2: Scan All Prompts")
    print("=" * 70)

    payload = {
        "server_url": MCP_SERVER_URL,
        "analyzers": ["llm"],
        "output_format": "raw",
    }

    async with httpx.AsyncClient(timeout=120.0) as client:
        response = await client.post(f"{BASE_URL}/scan-all-prompts", json=payload)

        if response.status_code == 200:
            result = response.json()
            print(f"\n✅ Total Prompts: {result['total_prompts']}")
            print(f"   Safe: {result['safe_prompts']}")
            print(f"   Unsafe: {result['unsafe_prompts']}")
            print(f"\n   Prompts:")
            for prompt in result['prompts']:
                status = "✅ SAFE" if prompt['is_safe'] else "⚠️  UNSAFE"
                print(f"      {status} {prompt['prompt_name']}")
        else:
            print(f"❌ Error: {response.status_code}")
            print(response.text)
    print()


async def test_scan_resource():
    """Test scanning a specific resource."""
    print("=" * 70)
    print("TEST 3: Scan Specific Resource")
    print("=" * 70)

    payload = {
        "server_url": MCP_SERVER_URL,
        "tool_name": "file://test/malicious_script.html",  # Using tool_name field for resource_uri
        "analyzers": ["llm"],
        "output_format": "raw",
    }

    async with httpx.AsyncClient(timeout=60.0) as client:
        response = await client.post(
            f"{BASE_URL}/scan-resource",
            json=payload,
            params={"allowed_mime_types": ["text/plain", "text/html"]}
        )

        if response.status_code == 200:
            result = response.json()
            print(f"\n✅ Resource: {result['resource_name']}")
            print(f"   URI: {result['resource_uri']}")
            print(f"   MIME Type: {result['resource_mime_type']}")
            print(f"   Status: {result['status']}")
            print(f"   Safe: {result['is_safe']}")
            print(f"\n   Findings:")
            for analyzer, data in result['findings'].items():
                print(f"      {analyzer}: {data['severity']} - {data['threat_summary']}")
        else:
            print(f"❌ Error: {response.status_code}")
            print(response.text)
    print()


async def test_scan_all_resources():
    """Test scanning all resources."""
    print("=" * 70)
    print("TEST 4: Scan All Resources")
    print("=" * 70)

    payload = {
        "server_url": MCP_SERVER_URL,
        "analyzers": ["llm"],
        "output_format": "raw",
    }

    async with httpx.AsyncClient(timeout=120.0) as client:
        response = await client.post(
            f"{BASE_URL}/scan-all-resources",
            json=payload,
            params={"allowed_mime_types": ["text/plain", "text/html"]}
        )

        if response.status_code == 200:
            result = response.json()
            print(f"\n✅ Total Resources: {result['total_resources']}")
            print(f"   Scanned: {result['scanned_resources']}")
            print(f"   Skipped: {result['skipped_resources']}")
            print(f"   Safe: {result['safe_resources']}")
            print(f"   Unsafe: {result['unsafe_resources']}")
            print(f"\n   Resources:")
            for resource in result['resources']:
                if resource['status'] == 'completed':
                    status = "✅ SAFE" if resource['is_safe'] else "⚠️  UNSAFE"
                    print(f"      {status} {resource['resource_name']} ({resource['resource_mime_type']})")
                else:
                    print(f"      ⏭️  SKIPPED {resource['resource_name']} ({resource['status']})")
        else:
            print(f"❌ Error: {response.status_code}")
            print(response.text)
    print()


async def main():
    print("\n" + "=" * 70)
    print("Testing Prompt and Resource API Endpoints")
    print("=" * 70)
    print()

    try:
        await test_scan_prompt()
        await test_scan_all_prompts()
        await test_scan_resource()
        await test_scan_all_resources()

        print("=" * 70)
        print("✅ All API endpoint tests completed!")
        print("=" * 70)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
