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

"""Comprehensive example demonstrating prompt and resource scanning with proper output formatting.

This example shows how to:
1. Scan all prompts with detailed output
2. Scan all resources with detailed output
3. Display results in a user-friendly format
4. Generate summary statistics
"""

import asyncio
import os
from mcpscanner import Config, Scanner
from mcpscanner.core.models import AnalyzerEnum


def display_prompt_results(results, title="Prompt Scan Results"):
    """Display prompt scan results in a formatted way."""
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)

    if not results:
        print("No prompts found.")
        return

    # Calculate statistics
    safe_prompts = [r for r in results if r.is_safe]
    unsafe_prompts = [r for r in results if not r.is_safe]

    print(f"\n📊 Summary:")
    print(f"   Total prompts: {len(results)}")
    print(f"   ✅ Safe: {len(safe_prompts)}")
    print(f"   ⚠️  Unsafe: {len(unsafe_prompts)}")

    # Display unsafe prompts first
    if unsafe_prompts:
        print(f"\n⚠️  Unsafe Prompts ({len(unsafe_prompts)}):")
        print("-" * 70)
        for i, result in enumerate(unsafe_prompts, 1):
            print(f"\n{i}. {result.prompt_name}")
            if result.prompt_description:
                desc = result.prompt_description
                print(f"   Description: {desc[:80]}{'...' if len(desc) > 80 else ''}")
            print(f"   Status: {result.status}")
            print(f"   Analyzers: {', '.join([str(a) for a in result.analyzers])}")

            if result.findings:
                print(f"   🔍 Findings ({len(result.findings)}):")
                for j, finding in enumerate(result.findings, 1):
                    print(f"      {j}. [{finding.severity}] {finding.summary}")
                    print(f"         Analyzer: {finding.analyzer}")
                    if finding.details and finding.details.get("primary_threats"):
                        threats = ", ".join(finding.details["primary_threats"])
                        print(f"         Threats: {threats}")

    # Display safe prompts
    if safe_prompts:
        print(f"\n✅ Safe Prompts ({len(safe_prompts)}):")
        print("-" * 70)
        for i, result in enumerate(safe_prompts, 1):
            print(f"{i}. {result.prompt_name}")
            if result.prompt_description:
                desc = result.prompt_description
                print(f"   Description: {desc[:80]}{'...' if len(desc) > 80 else ''}")


def display_resource_results(results, title="Resource Scan Results"):
    """Display resource scan results in a formatted way."""
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)

    if not results:
        print("No resources found.")
        return

    # Calculate statistics
    completed = [r for r in results if r.status == "completed"]
    skipped = [r for r in results if r.status == "skipped"]
    failed = [r for r in results if r.status == "failed"]
    safe_resources = [r for r in completed if r.is_safe]
    unsafe_resources = [r for r in completed if not r.is_safe]

    print(f"\n📊 Summary:")
    print(f"   Total resources: {len(results)}")
    print(f"   ✅ Scanned: {len(completed)}")
    print(f"   ⏭️  Skipped: {len(skipped)}")
    print(f"   ❌ Failed: {len(failed)}")
    if completed:
        print(f"   ✅ Safe: {len(safe_resources)}")
        print(f"   ⚠️  Unsafe: {len(unsafe_resources)}")

    # Display unsafe resources first
    if unsafe_resources:
        print(f"\n⚠️  Unsafe Resources ({len(unsafe_resources)}):")
        print("-" * 70)
        for i, result in enumerate(unsafe_resources, 1):
            print(f"\n{i}. {result.resource_name}")
            print(f"   URI: {result.resource_uri}")
            print(f"   MIME Type: {result.resource_mime_type}")
            print(f"   Analyzers: {', '.join([str(a) for a in result.analyzers])}")

            if result.findings:
                print(f"   🔍 Findings ({len(result.findings)}):")
                for j, finding in enumerate(result.findings, 1):
                    print(f"      {j}. [{finding.severity}] {finding.summary}")
                    print(f"         Analyzer: {finding.analyzer}")
                    if finding.details and finding.details.get("primary_threats"):
                        threats = ", ".join(finding.details["primary_threats"])
                        print(f"         Threats: {threats}")

    # Display safe resources
    if safe_resources:
        print(f"\n✅ Safe Resources ({len(safe_resources)}):")
        print("-" * 70)
        for i, result in enumerate(safe_resources, 1):
            print(f"{i}. {result.resource_name}")
            print(f"   URI: {result.resource_uri}")
            print(f"   MIME Type: {result.resource_mime_type}")

    # Display skipped resources
    if skipped:
        print(f"\n⏭️  Skipped Resources ({len(skipped)}):")
        print("-" * 70)
        for i, result in enumerate(skipped, 1):
            print(f"{i}. {result.resource_name}")
            print(f"   URI: {result.resource_uri}")
            print(f"   MIME Type: {result.resource_mime_type}")
            print(f"   Reason: Unsupported MIME type")


async def scan_prompts_example():
    """Example: Scan all prompts with formatted output."""
    print("\n" + "=" * 70)
    print("Example 1: Scanning Prompts")
    print("=" * 70)

    # Configure scanner
    config = Config(
        api_key=os.getenv("MCP_SCANNER_API_KEY"),
        llm_provider_api_key=os.getenv("MCP_SCANNER_LLM_API_KEY"),
        llm_model=os.getenv("MCP_SCANNER_LLM_MODEL", "gpt-4o"),
        llm_base_url=os.getenv("MCP_SCANNER_LLM_BASE_URL"),
        llm_api_version=os.getenv("MCP_SCANNER_LLM_API_VERSION"),
    )

    scanner = Scanner(config)

    # Replace with your MCP server URL
    server_url = "http://127.0.0.1:8000/mcp"

    print(f"\n🔍 Scanning prompts from: {server_url}")
    print(f"📋 Analyzers: LLM")

    try:
        # Scan all prompts
        results = await scanner.scan_remote_server_prompts(
            server_url,
            analyzers=[AnalyzerEnum.LLM]
        )

        # Display formatted results
        display_prompt_results(results, "Prompt Scan Results")

    except Exception as e:
        print(f"\n❌ Error scanning prompts: {e}")
        import traceback
        traceback.print_exc()


async def scan_resources_example():
    """Example: Scan all resources with formatted output."""
    print("\n" + "=" * 70)
    print("Example 2: Scanning Resources")
    print("=" * 70)

    # Configure scanner
    config = Config(
        api_key=os.getenv("MCP_SCANNER_API_KEY"),
        llm_provider_api_key=os.getenv("MCP_SCANNER_LLM_API_KEY"),
        llm_model=os.getenv("MCP_SCANNER_LLM_MODEL", "gpt-4o"),
        llm_base_url=os.getenv("MCP_SCANNER_LLM_BASE_URL"),
        llm_api_version=os.getenv("MCP_SCANNER_LLM_API_VERSION"),
    )

    scanner = Scanner(config)

    # Replace with your MCP server URL
    server_url = "http://127.0.0.1:8000/mcp"

    print(f"\n🔍 Scanning resources from: {server_url}")
    print(f"📋 Analyzers: LLM")
    print(f"📄 Allowed MIME types: text/plain, text/html")

    try:
        # Scan all resources
        results = await scanner.scan_remote_server_resources(
            server_url,
            analyzers=[AnalyzerEnum.LLM],
            allowed_mime_types=["text/plain", "text/html"]
        )

        # Display formatted results
        display_resource_results(results, "Resource Scan Results")

    except Exception as e:
        print(f"\n❌ Error scanning resources: {e}")
        import traceback
        traceback.print_exc()


async def scan_specific_prompt_example():
    """Example: Scan a specific prompt."""
    print("\n" + "=" * 70)
    print("Example 3: Scanning Specific Prompt")
    print("=" * 70)

    config = Config(
        llm_provider_api_key=os.getenv("MCP_SCANNER_LLM_API_KEY"),
        llm_model=os.getenv("MCP_SCANNER_LLM_MODEL", "gpt-4o"),
        llm_base_url=os.getenv("MCP_SCANNER_LLM_BASE_URL"),
        llm_api_version=os.getenv("MCP_SCANNER_LLM_API_VERSION"),
    )

    scanner = Scanner(config)
    server_url = "http://127.0.0.1:8000/mcp"
    prompt_name = "execute_system_command"

    print(f"\n🔍 Scanning prompt: '{prompt_name}'")
    print(f"🌐 Server: {server_url}")

    try:
        result = await scanner.scan_remote_server_prompt(
            server_url,
            prompt_name,
            analyzers=[AnalyzerEnum.LLM]
        )

        # Display single result
        display_prompt_results([result], f"Scan Result for '{prompt_name}'")

    except ValueError as e:
        print(f"\n❌ Prompt not found: {e}")
    except Exception as e:
        print(f"\n❌ Error: {e}")


async def scan_specific_resource_example():
    """Example: Scan a specific resource."""
    print("\n" + "=" * 70)
    print("Example 4: Scanning Specific Resource")
    print("=" * 70)

    config = Config(
        llm_provider_api_key=os.getenv("MCP_SCANNER_LLM_API_KEY"),
        llm_model=os.getenv("MCP_SCANNER_LLM_MODEL", "gpt-4o"),
        llm_base_url=os.getenv("MCP_SCANNER_LLM_BASE_URL"),
        llm_api_version=os.getenv("MCP_SCANNER_LLM_API_VERSION"),
    )

    scanner = Scanner(config)
    server_url = "http://127.0.0.1:8000/mcp"
    resource_uri = "file://test/malicious_script.html"

    print(f"\n🔍 Scanning resource: '{resource_uri}'")
    print(f"🌐 Server: {server_url}")

    try:
        result = await scanner.scan_remote_server_resource(
            server_url,
            resource_uri,
            analyzers=[AnalyzerEnum.LLM],
            allowed_mime_types=["text/plain", "text/html"]
        )

        # Display single result
        display_resource_results([result], f"Scan Result for '{resource_uri}'")

    except ValueError as e:
        print(f"\n❌ Resource not found: {e}")
    except Exception as e:
        print(f"\n❌ Error: {e}")


def main():
    """Run all examples."""
    print("\n" + "=" * 70)
    print("MCP Scanner - Prompts & Resources Examples")
    print("=" * 70)

    # Check for required environment variables
    if not os.getenv("MCP_SCANNER_LLM_API_KEY"):
        print("\n⚠️  Warning: MCP_SCANNER_LLM_API_KEY not set")
        print("Please set the environment variable to run these examples.")
        return

    print("\nRunning all examples...")

    # Run all examples
    asyncio.run(scan_prompts_example())
    asyncio.run(scan_resources_example())
    asyncio.run(scan_specific_prompt_example())
    asyncio.run(scan_specific_resource_example())

    print("\n" + "=" * 70)
    print("✅ All examples completed!")
    print("=" * 70)


if __name__ == "__main__":
    main()
