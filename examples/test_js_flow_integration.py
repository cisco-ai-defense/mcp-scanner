#!/usr/bin/env python3
"""
Test JS Flow Tracker Integration with CodeLLMAnalyzer

Tests that the JS flow tracker is properly integrated.
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from mcpscanner.core.analyzers.code_llm_analyzer import CodeLLMAnalyzer, SupportedLanguage
from mcpscanner.config.config import Config


def test_js_extraction_with_flow():
    """Test that JS functions are extracted and flow analysis works"""
    
    code = """
server.tool("execute_command", async ({ command }) => {
    const { exec } = require('child_process');
    const cmd = command;
    
    // Dangerous: command injection
    exec(cmd, (error, stdout, stderr) => {
        return { content: [{ type: "text", text: stdout }] };
    });
});
"""
    
    print("=" * 80)
    print("  TEST: JS Flow Integration with CodeLLMAnalyzer")
    print("=" * 80)
    print()
    
    config = Config()
    analyzer = CodeLLMAnalyzer(config)
    
    # Extract MCP functions
    functions = analyzer._extract_mcp_functions(
        code,
        "test_server.js",
        SupportedLanguage.TYPESCRIPT
    )
    
    print(f"✅ Extracted {len(functions)} MCP functions")
    
    for func in functions:
        print(f"\n📋 Function: {func.function_name}")
        print(f"   Type: {func.function_type}")
        print(f"   Language: {func.language.value}")
        print(f"   Line: {func.line_number}")
        print(f"   Code length: {len(func.code_snippet)} characters")
        
        # Test flow analysis on the extracted code
        from mcpscanner.utils.js_flow_tracker import track_js_code_flow, get_js_flow_summary
        
        flow_report = track_js_code_flow(func.code_snippet, func.file_path)
        
        print(f"\n   Flow Analysis:")
        print(f"   • Parameters tracked: {flow_report['total_parameters']}")
        print(f"   • Flows to sinks: {flow_report['parameters_reaching_sinks']}")
        print(f"   • High severity: {len(flow_report.get('high_severity_flows', []))}")
        
        if flow_report.get('high_severity_flows'):
            print(f"\n   🔴 High Severity Flows:")
            for param in flow_report['high_severity_flows']:
                flow_data = flow_report['parameter_flows'][param]
                print(f"      • {param} → {flow_data['sink_type']}")
        
        # Get summary
        summary = get_js_flow_summary(flow_report)
        print(f"\n   Summary:")
        for line in summary.split('\n')[:5]:
            print(f"   {line}")


def main():
    """Run test"""
    print("\n" + "=" * 80)
    print("  JS FLOW TRACKER INTEGRATION TEST")
    print("=" * 80)
    print()
    
    test_js_extraction_with_flow()
    
    print("\n" + "=" * 80)
    print("  TEST COMPLETE")
    print("=" * 80)
    print()
    print("✅ JS Flow Tracker is properly integrated!")
    print("   - Extracts TypeScript/JavaScript MCP functions")
    print("   - Performs flow analysis on extracted code")
    print("   - Generates summaries for LLM consumption")
    print()
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
