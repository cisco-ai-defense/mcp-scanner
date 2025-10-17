#!/usr/bin/env python3
"""Example: Scan a GitHub repository for MCP server vulnerabilities.

This example demonstrates how to use the GitHub analyzer to scan
a public GitHub repository containing MCP server code for security
vulnerabilities using LLM-based analysis.
"""

import asyncio
import logging
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from mcpscanner import Config, Scanner
from mcpscanner.core.models import AnalyzerEnum

# Enable INFO logging (disable debug)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)


async def main():
    """Scan the MCP fetch server repository for vulnerabilities."""
    
    # Configure with Azure OpenAI credentials
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
    
    # Repository to scan
    repo_url = "https://github.com/modelcontextprotocol/servers"
    
    print("=" * 80)
    print("GitHub Repository Security Scan")
    print("=" * 80)
    print(f"\n📦 Repository: {repo_url}")
    print(f"🔍 Analyzer: Code LLM (LLM-based)")
    print("\n⏳ Scanning repository... This may take a few minutes.\n")
    
    try:
        # Scan the repository
        result = await scanner.scan_github_repository(
            repo_url=repo_url,
            analyzers=[AnalyzerEnum.CODE_LLM]
        )
        
        # Display results
        print("=" * 80)
        print("📊 SCAN RESULTS")
        print("=" * 80)
        print(f"\n✅ Status: {result.status}")
        print(f"📝 Total MCP Functions Found: {result.total_functions_found}")
        print(f"⚠️  Vulnerabilities Found: {result.vulnerabilities_found}")
        print(f"🛡️  Is Safe: {result.is_safe}")
        
        # Functions by type
        if result.functions_by_type:
            print("\n📋 Functions by Type:")
            for func_type, count in result.functions_by_type.items():
                print(f"   - {func_type}: {count}")
        
        # Functions by language
        if result.functions_by_language:
            print("\n💻 Functions by Language:")
            for language, count in result.functions_by_language.items():
                print(f"   - {language}: {count}")
        
        # Display findings
        if result.findings:
            print("\n" + "=" * 80)
            print("🔍 DETAILED FINDINGS")
            print("=" * 80)
            
            for analyzer_name, findings in result.findings.items():
                print(f"\n📌 {analyzer_name} Analyzer:")
                for i, finding in enumerate(findings, 1):
                    severity_emoji = {
                        "critical": "🔴",
                        "high": "🟠",
                        "medium": "🟡",
                        "low": "🟢",
                        "info": "ℹ️"
                    }.get(finding.get("severity", "info"), "ℹ️")
                    
                    print(f"\n{severity_emoji} Finding #{i} [{finding.get('severity', 'info').upper()}]")
                    print(f"   Summary: {finding.get('summary', 'N/A')}")
                    
                    # Parse details string to extract information
                    details = finding.get("details", "")
                    if isinstance(details, str) and details:
                        # Split by newlines and display each part
                        for line in details.split('\n'):
                            if line.strip():
                                print(f"   {line}")
                        
                        # Show code snippet if available
                        if "Code snippet:" in details or "code_snippet" in details.lower():
                            print(f"\n   📄 Code Snippet:")
                            # Extract and display code snippet
                            lines = details.split('\n')
                            in_code = False
                            for line in lines:
                                if 'code' in line.lower() or in_code:
                                    if line.strip():
                                        print(f"      {line}")
                                    in_code = True
                                    if in_code and not line.strip():
                                        break
        
        print("\n" + "=" * 80)
        print("✨ Scan Complete!")
        print("=" * 80)
        
        # Summary
        if result.is_safe:
            print("\n✅ The repository appears to be SAFE - no critical vulnerabilities detected.")
        else:
            print(f"\n⚠️  WARNING: Found {result.vulnerabilities_found} potential security issues.")
            print("   Please review the findings above and take appropriate action.")
        
    except Exception as e:
        print(f"\n❌ Error during scan: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
