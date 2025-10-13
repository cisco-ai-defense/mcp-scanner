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

"""Quick test of prompt scanning on HTTP server."""

import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from mcpscanner import Config, Scanner
from mcpscanner.core.models import AnalyzerEnum


async def main():
    print("=" * 70)
    print("Quick Test: Scanning HTTP MCP Server Prompts")
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
    print("Analyzers: LLM + YARA\n")

    try:
        results = await scanner.scan_remote_server_prompts(
            server_url,
            analyzers=[AnalyzerEnum.LLM, AnalyzerEnum.YARA]
        )

        print(f"✅ Scanned {len(results)} prompts\n")

        for result in results:
            status = "✅ SAFE" if result.is_safe else "⚠️  UNSAFE"
            print(f"{status} {result.prompt_name}")
            print(f"   {result.prompt_description[:60]}...")

            if not result.is_safe:
                for finding in result.findings:
                    print(f"   [{finding.analyzer}] {finding.severity}: {finding.summary}")
            print()

        # Summary
        safe = sum(1 for r in results if r.is_safe)
        unsafe = len(results) - safe
        print(f"Summary: {safe} safe, {unsafe} unsafe")

    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
