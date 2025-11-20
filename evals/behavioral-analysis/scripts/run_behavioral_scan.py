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
Script to run behavioral MCP scanner against evaluation data.

This script scans all malicious MCP server implementations in the data directory
to evaluate the behavioral analyzer's detection capabilities.
"""

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Any

from mcpscanner import Config
from mcpscanner.core.analyzers.behavioral import BehavioralCodeAnalyzer


async def scan_file(analyzer: BehavioralCodeAnalyzer, filepath: Path) -> Dict[str, Any]:
    """Scan a single file and return results."""
    try:
        # Read the file content
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Analyze the file with context
        context = {
            "file_path": str(filepath),
            "file_name": filepath.name
        }
        findings = await analyzer.analyze(content, context)
        
        return {
            "file": str(filepath.relative_to(Path(__file__).parent.parent)),
            "status": "completed",
            "is_safe": len(findings) == 0,
            "findings_count": len(findings),
            "findings": [
                {
                    "severity": f.severity,
                    "summary": f.summary,
                    "threat_category": f.threat_category,
                }
                for f in findings
            ]
        }
    except Exception as e:
        return {
            "file": str(filepath.relative_to(Path(__file__).parent.parent)),
            "status": "error",
            "error": str(e)
        }


async def scan_category(analyzer: BehavioralCodeAnalyzer, category_dir: Path) -> List[Dict[str, Any]]:
    """Scan all files in a threat category directory."""
    results = []
    
    # Find all Python files in the category
    py_files = list(category_dir.glob("*.py"))
    
    print(f"\n📁 Scanning {category_dir.name}: {len(py_files)} files")
    
    for py_file in py_files:
        print(f"  🔍 {py_file.name}...", end=" ")
        result = await scan_file(analyzer, py_file)
        results.append(result)
        
        if result.get("status") == "error":
            print(f"❌ ERROR")
        elif result.get("is_safe"):
            print(f"⚠️  MISSED (no findings)")
        else:
            print(f"✅ DETECTED ({result['findings_count']} findings)")
    
    return results


async def main():
    """Main function to run behavioral scans."""
    print("=" * 80)
    print("Behavioral Analysis Evaluation Scanner")
    print("=" * 80)
    
    # Get the data directory
    script_dir = Path(__file__).parent
    data_dir = script_dir.parent / "data"
    
    if not data_dir.exists():
        print(f"❌ Error: Data directory not found: {data_dir}")
        sys.exit(1)
    
    print(f"\n📂 Data directory: {data_dir}")
    
    # Create analyzer with configuration from environment
    config = Config(
        llm_provider_api_key=os.getenv("MCP_SCANNER_LLM_API_KEY"),
        llm_model=os.getenv("MCP_SCANNER_LLM_MODEL"),
        llm_base_url=os.getenv("MCP_SCANNER_LLM_BASE_URL"),
        llm_api_version=os.getenv("MCP_SCANNER_LLM_API_VERSION"),
    )
    
    # Check if LLM is configured
    if not config.llm_provider_api_key:
        print("\n❌ Error: LLM configuration required for behavioral analysis")
        print("\nPlease set the following environment variables:")
        print("  export MCP_SCANNER_LLM_API_KEY='your_api_key'")
        print("  export MCP_SCANNER_LLM_MODEL='azure/gpt-4.1'  # or other model")
        print("  export MCP_SCANNER_LLM_BASE_URL='https://your-endpoint.openai.azure.com/'")
        print("  export MCP_SCANNER_LLM_API_VERSION='2024-02-15-preview'")
        sys.exit(1)
    
    print(f"🤖 LLM Model: {config.llm_model}")
    
    analyzer = BehavioralCodeAnalyzer(config)
    
    # Get all threat category directories
    categories = sorted([d for d in data_dir.iterdir() if d.is_dir()])
    
    print(f"📊 Found {len(categories)} threat categories")
    
    # Scan each category
    all_results = {}
    total_files = 0
    total_detected = 0
    total_missed = 0
    total_errors = 0
    
    for category_dir in categories:
        category_results = await scan_category(analyzer, category_dir)
        all_results[category_dir.name] = category_results
        
        # Update statistics
        total_files += len(category_results)
        for result in category_results:
            if result.get("status") == "error":
                total_errors += 1
            elif result.get("is_safe"):
                total_missed += 1
            else:
                total_detected += 1
    
    # Print summary
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"Total files scanned: {total_files}")
    print(f"✅ Detected (with findings): {total_detected}")
    print(f"⚠️  Missed (no findings): {total_missed}")
    print(f"❌ Errors: {total_errors}")
    
    if total_files > 0:
        detection_rate = (total_detected / total_files) * 100
        print(f"\n🎯 Detection Rate: {detection_rate:.1f}%")
    
    # Save detailed results to JSON
    output_file = script_dir / "scan_results.json"
    with open(output_file, "w") as f:
        json.dump({
            "summary": {
                "total_files": total_files,
                "detected": total_detected,
                "missed": total_missed,
                "errors": total_errors,
                "detection_rate": f"{detection_rate:.1f}%" if total_files > 0 else "N/A"
            },
            "results_by_category": all_results
        }, f, indent=2)
    
    print(f"\n💾 Detailed results saved to: {output_file}")
    print("=" * 80)
    
    return 0 if total_errors == 0 else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
