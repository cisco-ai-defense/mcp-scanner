#!/usr/bin/env python3
"""Test scanning a local MCP server file with malicious tools."""

import asyncio
import logging
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from mcpscanner import Config, Scanner
from mcpscanner.core.models import AnalyzerEnum

# Enable INFO logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)


async def main():
    """Scan the local mcp_complete_server.py file."""
    
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
    
    # Initialize scanner
    scanner = Scanner(config)
    
    # Create a temporary git repo with our test file
    import tempfile
    import shutil
    from git import Repo
    
    temp_dir = tempfile.mkdtemp(prefix="mcp_test_")
    
    try:
        print("=" * 80)
        print("Local MCP Server Security Scan")
        print("=" * 80)
        print(f"\n📦 File: examples/mcp_complete_server.py")
        print(f"🔍 Analyzer: GitHub (LLM-based)")
        print("\n⏳ Scanning file... This may take a few minutes.\n")
        
        # Initialize git repo
        repo = Repo.init(temp_dir)
        
        # Copy the test file
        test_file = Path(__file__).parent / "mcp_complete_server.py"
        dest_file = Path(temp_dir) / "mcp_complete_server.py"
        shutil.copy(test_file, dest_file)
        
        # Commit it
        repo.index.add(["mcp_complete_server.py"])
        repo.index.commit("Initial commit")
        
        # Scan using the Code LLM analyzer directly
        from mcpscanner.core.analyzers.code_llm_analyzer import CodeLLMAnalyzer
        
        code_llm_analyzer = CodeLLMAnalyzer(config)
        
        # Read and analyze the file
        with open(dest_file, 'r') as f:
            file_content = f.read()
        
        from mcpscanner.core.analyzers.code_llm_analyzer import SupportedLanguage
        functions = code_llm_analyzer._extract_mcp_functions(
            file_content, 
            "mcp_complete_server.py",
            SupportedLanguage.PYTHON
        )
        
        print(f"✅ Found {len(functions)} MCP functions\n")
        
        # Analyze each function
        all_findings = []
        for func in functions:
            print(f"🔍 Analyzing: {func.function_name} ({func.function_type})")
            findings = await code_llm_analyzer._analyze_function_with_llm(func)
            all_findings.extend(findings)
        
        # Display results
        print("\n" + "=" * 80)
        print("📊 SCAN RESULTS")
        print("=" * 80)
        print(f"\n📝 Total MCP Functions Found: {len(functions)}")
        print(f"⚠️  Vulnerabilities Found: {len([f for f in all_findings if f.severity in ['high', 'critical']])}")
        
        # Display findings
        if all_findings:
            print("\n" + "=" * 80)
            print("🔍 DETAILED FINDINGS")
            print("=" * 80)
            
            for i, finding in enumerate(all_findings, 1):
                severity_emoji = {
                    "critical": "🔴",
                    "high": "🟠",
                    "medium": "🟡",
                    "low": "🟢",
                    "info": "ℹ️"
                }.get(finding.severity, "ℹ️")
                
                print(f"\n{severity_emoji} Finding #{i} [{finding.severity.upper()}]")
                print(f"   Summary: {finding.summary}")
                print(f"   Category: {finding.threat_category}")
                
                # Display details
                if finding.details:
                    for line in finding.details.split('\n'):
                        if line.strip():
                            print(f"   {line}")
        
        print("\n" + "=" * 80)
        print("✨ Scan Complete!")
        print("=" * 80)
        
    finally:
        # Cleanup
        shutil.rmtree(temp_dir, ignore_errors=True)
    
    return 0


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
