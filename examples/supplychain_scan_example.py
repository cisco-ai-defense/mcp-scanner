"""Example: Using the SupplyChain Analyzer to detect docstring/behavior mismatches.

This example demonstrates how to use the SupplyChain analyzer to scan MCP server
source code and detect mismatches between what the docstring claims and what the
code actually does (e.g., data exfiltration, hidden behaviors).
"""

import asyncio
import os
from mcpscanner import Config, Scanner
from mcpscanner.core.models import AnalyzerEnum


async def main():
    """Scan MCP server source code for docstring/behavior mismatches."""
    
    # Configure with Azure OpenAI credentials
    config = Config(
        llm_provider_api_key=os.getenv("MCP_SCANNER_LLM_API_KEY"),
        llm_base_url=os.getenv("MCP_SCANNER_LLM_BASE_URL"),
        llm_api_version=os.getenv("MCP_SCANNER_LLM_API_VERSION"),
        llm_model=os.getenv("MCP_SCANNER_LLM_MODEL", "azure/gpt-4"),
    )
    
    # Create scanner with supplychain analyzer
    scanner = Scanner(config)
    
    # Path to MCP server source code
    source_path = "path/to/your/mcp_server.py"
    
    print(f"🔍 Scanning MCP server source code: {source_path}")
    print("   Analyzer: SupplyChain (Deep Code Analysis + LLM)")
    print()
    
    # Directly use the supplychain analyzer
    from mcpscanner.core.analyzers.supplychain_analyzer import SupplyChainAnalyzer
    
    analyzer = SupplyChainAnalyzer(config)
    findings = await analyzer.analyze(
        source_path,
        context={"file_path": source_path}
    )
    
    print("=" * 70)
    print(f"📊 ANALYSIS RESULTS: {len(findings)} finding(s)")
    print("=" * 70)
    print()
    
    if not findings:
        print("✅ No mismatches detected - docstrings match implementation")
    else:
        for i, finding in enumerate(findings, 1):
            print(f"🚨 Finding #{i}:")
            print(f"   Severity: {finding.severity}")
            print(f"   Category: {finding.threat_category}")
            print(f"   Summary: {finding.summary}")
            print()
            
            if finding.details:
                details = finding.details
                if 'description_claims' in details:
                    print(f"   📝 Docstring claims: {details['description_claims']}")
                if 'actual_behavior' in details:
                    print(f"   ⚙️  Actual behavior: {details['actual_behavior']}")
                if 'security_implications' in details:
                    print(f"   ⚠️  Security risk: {details['security_implications']}")
                if 'dataflow_evidence' in details:
                    print(f"   🔬 Evidence: {details['dataflow_evidence']}")
            print()


if __name__ == "__main__":
    asyncio.run(main())
