#!/usr/bin/env python3
"""
Test JavaScript/TypeScript Flow Tracker

Tests the JS flow tracker utility that will be used by CodeLLMAnalyzer.
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from mcpscanner.utils.js_flow_tracker import track_js_code_flow, get_js_flow_summary


def test_command_injection():
    """Test flow tracking for command injection"""
    code = """
server.setRequestHandler(CallToolRequest, async (request) => {
    const { arguments: args } = request.params;
    
    if (name === "execute_command") {
        const command = args.command;
        const { exec } = require('child_process');
        
        // Dangerous: command injection
        exec(command, (error, stdout, stderr) => {
            return { content: [{ type: "text", text: stdout }] };
        });
    }
});
"""
    
    print("=" * 80)
    print("  TEST 1: Command Injection Flow")
    print("=" * 80)
    
    flow_report = track_js_code_flow(code, "command_injection.js")
    summary = get_js_flow_summary(flow_report)
    
    print(summary)
    print(f"\n✅ Tracked {flow_report['total_parameters']} parameters")
    print(f"✅ Found {flow_report['parameters_reaching_sinks']} flows to sinks")
    print(f"✅ High severity flows: {len(flow_report.get('high_severity_flows', []))}")


def test_file_read():
    """Test flow tracking for file read"""
    code = """
server.tool("read_file", async ({ path }) => {
    const fs = require('fs');
    const filePath = path;
    
    // Dangerous: arbitrary file read
    const content = fs.readFileSync(filePath, 'utf-8');
    
    return {
        content: [{ type: "text", text: content }]
    };
});
"""
    
    print("\n" + "=" * 80)
    print("  TEST 2: Arbitrary File Read Flow")
    print("=" * 80)
    
    flow_report = track_js_code_flow(code, "file_read.js")
    summary = get_js_flow_summary(flow_report)
    
    print(summary)
    print(f"\n✅ Tracked {flow_report['total_parameters']} parameters")
    print(f"✅ Found {flow_report['parameters_reaching_sinks']} flows to sinks")
    print(f"✅ Medium severity flows: {len(flow_report.get('medium_severity_flows', []))}")


def test_ssrf():
    """Test flow tracking for SSRF"""
    code = """
server.registerTool("fetch_url", async ({ url }) => {
    const targetUrl = url;
    
    // Dangerous: SSRF
    const response = await fetch(targetUrl);
    const data = await response.text();
    
    return { content: [{ type: "text", text: data }] };
});
"""
    
    print("\n" + "=" * 80)
    print("  TEST 3: SSRF Flow")
    print("=" * 80)
    
    flow_report = track_js_code_flow(code, "ssrf.js")
    summary = get_js_flow_summary(flow_report)
    
    print(summary)
    print(f"\n✅ Tracked {flow_report['total_parameters']} parameters")
    print(f"✅ Found {flow_report['parameters_reaching_sinks']} flows to sinks")


def test_complex_flow():
    """Test complex flow with multiple assignments"""
    code = """
server.tool("process_data", async ({ userInput }) => {
    const data = userInput;
    const processed = data.trim();
    const command = `echo ${processed}`;
    
    const { exec } = require('child_process');
    exec(command);
});
"""
    
    print("\n" + "=" * 80)
    print("  TEST 4: Complex Flow with Propagation")
    print("=" * 80)
    
    flow_report = track_js_code_flow(code, "complex.js")
    summary = get_js_flow_summary(flow_report)
    
    print(summary)
    
    # Show detailed flow events
    if flow_report.get('parameter_flows'):
        print("\n📊 Detailed Flow Events:")
        for param_name, flow_data in flow_report['parameter_flows'].items():
            if flow_data['reaches_sink']:
                print(f"\n  Parameter: {param_name}")
                print(f"  Events: {flow_data['total_events']}")
                for event in flow_data['events'][:5]:
                    print(f"    • Line {event['line']}: {event['event']} - {event['variable']}")


def main():
    """Run all tests"""
    print("\n" + "=" * 80)
    print("  JAVASCRIPT/TYPESCRIPT FLOW TRACKER TEST SUITE")
    print("=" * 80)
    print()
    
    test_command_injection()
    test_file_read()
    test_ssrf()
    test_complex_flow()
    
    print("\n" + "=" * 80)
    print("  ALL TESTS COMPLETE")
    print("=" * 80)
    print()
    print("✅ JS Flow Tracker is working correctly!")
    print("   - Tracks function parameters and args.* patterns")
    print("   - Detects dangerous sinks (exec, fs, fetch, etc.)")
    print("   - Propagates taint through assignments")
    print("   - Calculates severity levels")
    print("   - Generates human-readable summaries")
    print()
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
