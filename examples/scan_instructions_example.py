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
Example: Scanning Server Instructions

This example demonstrates how to scan the instructions field from an
MCP server's InitializeResult response. Server instructions often contain
usage guidelines, security notes, and configuration details that should
be analyzed for potential security issues.

Prerequisites:
    - Start the example server: python examples/instructions_server.py
    - Set LLM API credentials in environment variables

Usage:
    python examples/scan_instructions_example.py
"""

import asyncio
import sys
import os

# Add parent directory to path to import mcpscanner
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcpscanner import Config, Scanner
from mcpscanner.core.models import AnalyzerEnum


async def scan_instructions_example():
    """Example of scanning instructions from an MCP server."""
    
    print("=" * 80)
    print("Testing Instructions Scanning")
    print("=" * 80)
    
    # Server URL (make sure the test server is running)
    server_url = "http://127.0.0.1:8001/mcp"
    
    print(f"\n🔍 Scanning instructions from: {server_url}")
    print("   Analyzers: LLM (Azure OpenAI)")
    
    # Create config with LLM credentials
    config = Config(
        api_key="",
        endpoint_url="",
        llm_provider_api_key=os.environ.get("MCP_SCANNER_LLM_API_KEY", ""),
        llm_base_url=os.environ.get("MCP_SCANNER_LLM_BASE_URL", ""),
        llm_api_version=os.environ.get("MCP_SCANNER_LLM_API_VERSION", ""),
        llm_model=os.environ.get("MCP_SCANNER_LLM_MODEL", ""),
    )
    
    # Create scanner with LLM analyzer
    scanner = Scanner(config)
    
    try:
        # Scan the instructions with LLM
        result = await scanner.scan_remote_server_instructions(
            server_url=server_url,
            analyzers=[AnalyzerEnum.LLM]
        )
        
        print("\n" + "=" * 80)
        print("Scan Results")
        print("=" * 80)
        
        print(f"\n📋 Server Name: {result.server_name}")
        print(f"🔢 Protocol Version: {result.protocol_version}")
        print(f"📊 Status: {result.status}")
        
        if result.instructions:
            print(f"\n📝 Instructions (first 200 chars):")
            print(f"   {result.instructions[:200]}...")
        else:
            print("\n📝 Instructions: (not provided)")
        
        print(f"\n🔒 Security Status: {'✅ SAFE' if result.is_safe else '⚠️  UNSAFE'}")
        print(f"🔍 Analyzers Run: {', '.join(str(a) for a in result.analyzers)}")
        print(f"🚨 Total Findings: {len(result.findings)}")
        
        if result.findings:
            print("\n" + "=" * 80)
            print("Security Findings")
            print("=" * 80)
            
            for i, finding in enumerate(result.findings, 1):
                print(f"\n{i}. {finding.summary}")
                print(f"   Severity: {finding.severity}")
                print(f"   Analyzer: {finding.analyzer}")
                
                if finding.details:
                    threat_type = finding.details.get("threat_type")
                    if threat_type:
                        print(f"   Threat Type: {threat_type}")
                
                # Display MCP Taxonomy if available
                if hasattr(finding, "mcp_taxonomy") and finding.mcp_taxonomy:
                    taxonomy = finding.mcp_taxonomy
                    if taxonomy.get("aitech"):
                        print(f"   Technique: {taxonomy.get('aitech')} - {taxonomy.get('aitech_name')}")
                    if taxonomy.get("aisubtech"):
                        print(f"   Sub-Technique: {taxonomy.get('aisubtech')} - {taxonomy.get('aisubtech_name')}")
        else:
            print("\n✅ No security findings detected in instructions.")
        
        print("\n" + "=" * 80)
        print("Test completed successfully!")
        print("=" * 80)
        
    except Exception as e:
        print(f"\n❌ Error during scan: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    print("\n⚠️  Make sure the instructions server is running:")
    print("   python examples/instructions_server.py")
    print()
    
    exit_code = asyncio.run(scan_instructions_example())
    sys.exit(exit_code)
