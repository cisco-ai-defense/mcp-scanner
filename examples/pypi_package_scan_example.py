#!/usr/bin/env python3
"""Example: Scan a PyPI package for security vulnerabilities."""

import asyncio
import logging
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from mcpscanner import Config
from mcpscanner.core.analyzers.pypi_package_analyzer import PyPIPackageAnalyzer

# Enable INFO logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)


async def main():
    """Scan a PyPI package for vulnerabilities."""
    
    # Configure with LLM credentials from environment variables
    # Set these environment variables before running:
    # - MCP_SCANNER_LLM_API_KEY
    # - MCP_SCANNER_LLM_BASE_URL
    # - MCP_SCANNER_LLM_MODEL
    # - MCP_SCANNER_LLM_API_VERSION
    import os
    
    config = Config(
        llm_provider_api_key=os.environ.get("MCP_SCANNER_LLM_API_KEY", ""),
        llm_base_url=os.environ.get("MCP_SCANNER_LLM_BASE_URL", ""),
        llm_model=os.environ.get("MCP_SCANNER_LLM_MODEL", "gpt-4"),
        llm_api_version=os.environ.get("MCP_SCANNER_LLM_API_VERSION", ""),
        llm_max_tokens=2000,
        llm_temperature=0.1,
    )
    
    # Initialize PyPI analyzer
    analyzer = PyPIPackageAnalyzer(config)
    
    # Example 1: Scan latest version of a package
    print("=" * 80)
    print("PyPI Package Security Scan - Example 1")
    print("=" * 80)
    print(f"\n📦 Package: requests (latest version)")
    print("\n⏳ Scanning... This may take a few minutes.\n")
    
    findings = await analyzer.analyze("requests")
    
    print("\n" + "=" * 80)
    print("📊 SCAN RESULTS")
    print("=" * 80)
    print(f"\n⚠️  Total Findings: {len(findings)}")
    
    # Display findings
    if findings:
        print("\n" + "=" * 80)
        print("🔍 DETAILED FINDINGS")
        print("=" * 80)
        
        for i, finding in enumerate(findings, 1):
            severity_emoji = {
                "high": "🔴",
                "medium": "🟡",
                "low": "🟢",
                "info": "ℹ️"
            }.get(finding.severity.lower(), "ℹ️")
            
            print(f"\n{severity_emoji} Finding #{i} [{finding.severity.upper()}]")
            print(f"   Summary: {finding.summary}")
            print(f"   Category: {finding.threat_category}")
            
            # Display details
            if finding.details:
                for line in str(finding.details).split('\n'):
                    if line.strip():
                        print(f"   {line}")
    
    # Example 2: Scan specific version
    print("\n\n" + "=" * 80)
    print("PyPI Package Security Scan - Example 2")
    print("=" * 80)
    print(f"\n📦 Package: flask version 2.0.0")
    print("\n⏳ Scanning... This may take a few minutes.\n")
    
    findings = await analyzer.analyze("flask", context={"version": "2.0.0"})
    
    print("\n" + "=" * 80)
    print("📊 SCAN RESULTS")
    print("=" * 80)
    print(f"\n⚠️  Total Findings: {len(findings)}")
    
    print("\n" + "=" * 80)
    print("✨ Scan Complete!")
    print("=" * 80)
    
    return 0


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
