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

"""Test script to verify prompt scanning functionality."""

import asyncio
import os
from mcpscanner import Config, Scanner, PromptScanResult
from mcpscanner.core.models import AnalyzerEnum
from mcp.types import Prompt as MCPPrompt


async def test_analyze_prompt():
    """Test the _analyze_prompt method directly."""
    print("=" * 60)
    print("Test 1: Analyzing a single prompt")
    print("=" * 60)

    # Create a test prompt
    test_prompt = MCPPrompt(
        name="test_prompt",
        description="This is a test prompt that executes system commands and accesses files"
    )

    # Configure scanner (will use YARA only if no API keys)
    config = Config(
        api_key=os.getenv("MCP_SCANNER_API_KEY"),
        llm_provider_api_key=os.getenv("MCP_SCANNER_LLM_API_KEY"),
        llm_model=os.getenv("MCP_SCANNER_LLM_MODEL", "azure/gpt-4.1"),
        llm_base_url=os.getenv("MCP_SCANNER_LLM_BASE_URL", "https://aidefense-threatintel.openai.azure.com/"),
        llm_api_version=os.getenv("MCP_SCANNER_LLM_API_VERSION", "2024-02-01"),
    )

    scanner = Scanner(config)

    # Determine which analyzers to use based on available configuration
    analyzers = []
    if scanner._api_analyzer:
        analyzers.append(AnalyzerEnum.API)
        print("✓ API Analyzer available")
    else:
        print("✗ API Analyzer not available (no API key)")

    if scanner._llm_analyzer:
        analyzers.append(AnalyzerEnum.LLM)
        print("✓ LLM Analyzer available")
    else:
        print("✗ LLM Analyzer not available (no LLM API key)")

    if scanner._yara_analyzer:
        analyzers.append(AnalyzerEnum.YARA)
        print("✓ YARA Analyzer available")

    if not analyzers:
        print("\n⚠️  No analyzers available. Please configure API keys.")
        return

    print(f"\nUsing analyzers: {', '.join([a.value for a in analyzers])}")
    print()

    # Analyze the prompt
    result = await scanner._analyze_prompt(test_prompt, analyzers)

    # Verify result
    assert isinstance(result, PromptScanResult), "Result should be PromptScanResult"
    assert result.prompt_name == "test_prompt", "Prompt name should match"
    assert result.status == "completed", "Status should be completed"

    print(f"Prompt: {result.prompt_name}")
    print(f"Description: {result.prompt_description}")
    print(f"Status: {result.status}")
    print(f"Analyzers used: {', '.join(result.analyzers)}")
    print(f"Safe: {result.is_safe}")
    print(f"Findings: {len(result.findings)}")

    if result.findings:
        print("\nFindings:")
        for finding in result.findings:
            print(f"  - [{finding.analyzer}] {finding.severity}: {finding.summary}")

    print("\n✅ Test 1 passed!\n")


async def test_prompt_scan_result_class():
    """Test the PromptScanResult class."""
    print("=" * 60)
    print("Test 2: PromptScanResult class")
    print("=" * 60)

    # Create a test result
    result = PromptScanResult(
        prompt_name="test_prompt",
        prompt_description="Test description",
        status="completed",
        analyzers=["API", "LLM"],
        findings=[],
        server_source="test_server",
        server_name="test"
    )

    # Test properties
    assert result.prompt_name == "test_prompt"
    assert result.is_safe == True, "Should be safe with no findings"
    assert result.status == "completed"

    print(f"Prompt: {result.prompt_name}")
    print(f"Safe: {result.is_safe}")
    print(f"String representation: {str(result)}")

    print("\n✅ Test 2 passed!\n")


async def test_method_signatures():
    """Test that all new methods exist and have correct signatures."""
    print("=" * 60)
    print("Test 3: Method signatures")
    print("=" * 60)

    config = Config()
    scanner = Scanner(config)

    # Check that methods exist
    assert hasattr(scanner, '_analyze_prompt'), "Should have _analyze_prompt method"
    assert hasattr(scanner, 'scan_remote_server_prompts'), "Should have scan_remote_server_prompts method"
    assert hasattr(scanner, 'scan_remote_server_prompt'), "Should have scan_remote_server_prompt method"
    assert hasattr(scanner, 'scan_stdio_server_prompts'), "Should have scan_stdio_server_prompts method"
    assert hasattr(scanner, 'scan_stdio_server_prompt'), "Should have scan_stdio_server_prompt method"

    print("✓ _analyze_prompt method exists")
    print("✓ scan_remote_server_prompts method exists")
    print("✓ scan_remote_server_prompt method exists")
    print("✓ scan_stdio_server_prompts method exists")
    print("✓ scan_stdio_server_prompt method exists")

    # Check method signatures
    import inspect

    sig = inspect.signature(scanner._analyze_prompt)
    params = list(sig.parameters.keys())
    assert 'prompt' in params, "Should have prompt parameter"
    assert 'analyzers' in params, "Should have analyzers parameter"
    print(f"\n_analyze_prompt signature: {sig}")

    sig = inspect.signature(scanner.scan_remote_server_prompts)
    params = list(sig.parameters.keys())
    assert 'server_url' in params, "Should have server_url parameter"
    assert 'analyzers' in params, "Should have analyzers parameter"
    print(f"scan_remote_server_prompts signature: {sig}")

    print("\n✅ Test 3 passed!\n")


async def test_imports():
    """Test that PromptScanResult is properly exported."""
    print("=" * 60)
    print("Test 4: Package imports")
    print("=" * 60)

    # Test direct import
    from mcpscanner import PromptScanResult as PSR
    assert PSR is not None, "PromptScanResult should be importable"
    print("✓ PromptScanResult can be imported from mcpscanner")

    # Test it's in __all__
    import mcpscanner
    assert 'PromptScanResult' in mcpscanner.__all__, "PromptScanResult should be in __all__"
    print("✓ PromptScanResult is in __all__")

    print("\n✅ Test 4 passed!\n")


async def main():
    """Run all tests."""
    print("\n" + "=" * 60)
    print("MCP Scanner - Prompt Scanning Tests")
    print("=" * 60)
    print()

    # Check environment
    has_api_key = bool(os.getenv("MCP_SCANNER_API_KEY"))
    has_llm_key = bool(os.getenv("MCP_SCANNER_LLM_API_KEY"))

    print("Environment Configuration:")
    print(f"  API Key: {'✓ Set' if has_api_key else '✗ Not set'}")
    print(f"  LLM API Key: {'✓ Set' if has_llm_key else '✗ Not set'}")

    if os.getenv("MCP_SCANNER_LLM_BASE_URL"):
        print(f"  LLM Base URL: {os.getenv('MCP_SCANNER_LLM_BASE_URL')}")
    if os.getenv("MCP_SCANNER_LLM_MODEL"):
        print(f"  LLM Model: {os.getenv('MCP_SCANNER_LLM_MODEL')}")

    print()

    try:
        # Run tests
        await test_imports()
        await test_prompt_scan_result_class()
        await test_method_signatures()
        await test_analyze_prompt()

        print("=" * 60)
        print("✅ All tests passed!")
        print("=" * 60)
        print()
        print("Summary:")
        print("  ✓ PromptScanResult class created")
        print("  ✓ _analyze_prompt method implemented")
        print("  ✓ scan_remote_server_prompts method implemented")
        print("  ✓ scan_remote_server_prompt method implemented")
        print("  ✓ scan_stdio_server_prompts method implemented")
        print("  ✓ scan_stdio_server_prompt method implemented")
        print("  ✓ All methods properly exported")
        print()
        print("Next steps:")
        print("  1. Test with a real MCP server that has prompts")
        print("  2. See examples/scan_prompts_example.py for usage examples")

    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    exit(exit_code)
