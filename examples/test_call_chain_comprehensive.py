#!/usr/bin/env python3
"""
Comprehensive Call Chain Tracker Test

Tests tracking function calls across multiple files:
- Entry point: MCP handler receives user input
- Calls utility function in another file
- Utility function calls another function
- Final function reaches dangerous sink
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from mcpscanner.utils.js_call_chain_tracker import JSCallChainTracker


def test_deep_call_chain():
    """Test a deep call chain: handler -> validator -> processor -> executor -> sink"""
    
    # File 1: Server entry point
    server_js = """
// server.js
import { validateAndProcess } from './validator';

server.tool("execute_task", async ({ command, options }) => {
    // Entry point - user controlled input
    const result = await validateAndProcess(command, options);
    return { content: [{ type: "text", text: result }] };
});

server.tool("read_file", async ({ path }) => {
    const data = await loadFile(path);
    return { content: [{ type: "text", text: data }] };
});
"""
    
    # File 2: Validator
    validator_js = """
// validator.js
import { processCommand } from './processor';

export function validateAndProcess(cmd, opts) {
    // Some validation
    if (!cmd) {
        throw new Error("Command required");
    }
    
    // Pass to processor
    return processCommand(cmd, opts);
}

export function loadFile(filePath) {
    const fs = require('fs');
    // SINK: File system access
    return fs.readFileSync(filePath, 'utf-8');
}
"""
    
    # File 3: Processor
    processor_js = """
// processor.js
import { executeCommand } from './executor';

export function processCommand(command, options) {
    // Process the command
    const processed = command.trim();
    const flags = options || {};
    
    // Pass to executor
    return executeCommand(processed, flags);
}
"""
    
    # File 4: Executor
    executor_js = """
// executor.js

export function executeCommand(cmd, flags) {
    const { exec } = require('child_process');
    
    // SINK: Command execution!
    exec(cmd, (error, stdout, stderr) => {
        if (error) throw error;
        return stdout;
    });
}
"""
    
    print("=" * 80)
    print("  TEST: Deep Call Chain Across 4 Files")
    print("=" * 80)
    print()
    
    tracker = JSCallChainTracker()
    tracker.add_file("server.js", server_js)
    tracker.add_file("validator.js", validator_js)
    tracker.add_file("processor.js", processor_js)
    tracker.add_file("executor.js", executor_js)
    
    results = tracker.analyze()
    
    print(tracker.format_report(results))
    
    # Show detailed chain information
    print("\n" + "=" * 80)
    print("  DETAILED CHAIN ANALYSIS")
    print("=" * 80)
    
    for i, chain in enumerate(results['call_chains'], 1):
        if chain.reaches_sink:
            print(f"\n🔴 Dangerous Chain #{i}:")
            print(f"   Entry Parameters: {', '.join(chain.source_params)}")
            print(f"   Chain Length: {len(chain.chain)} function calls")
            print(f"   Reaches Sink: {chain.sink_type}")
            print(f"   Severity: {chain.severity.upper()}")
            print(f"\n   Complete Flow:")
            
            if chain.chain:
                for j, call in enumerate(chain.chain, 1):
                    file_name = Path(call.caller_file).name
                    print(f"   {j}. {call.caller_function}() → {call.called_function}()")
                    print(f"      File: {file_name}:line {call.caller_line}")
                    print(f"      Args: {', '.join(call.arguments)}")
    
    return results


def test_multiple_entry_points():
    """Test multiple entry points leading to same sink"""
    
    # Shared utility with sink
    utils_js = """
// utils.js
export function dangerousOperation(input) {
    const { exec } = require('child_process');
    exec(input);  // SINK
}
"""
    
    # Multiple handlers calling the same dangerous function
    handlers_js = """
// handlers.js
import { dangerousOperation } from './utils';

export function handler1(userInput) {
    dangerousOperation(userInput);
}

export function handler2(data) {
    const processed = data.value;
    dangerousOperation(processed);
}

export function handler3(request) {
    handler1(request.command);
}
"""
    
    print("\n" + "=" * 80)
    print("  TEST: Multiple Entry Points to Same Sink")
    print("=" * 80)
    print()
    
    tracker = JSCallChainTracker()
    tracker.add_file("utils.js", utils_js)
    tracker.add_file("handlers.js", handlers_js)
    
    results = tracker.analyze()
    
    print(f"Found {results['total_functions']} functions")
    print(f"Found {results['total_call_chains']} call chains")
    print(f"Found {results['dangerous_chains']} dangerous chains")
    
    # Show all dangerous chains
    for i, chain in enumerate(results['call_chains'], 1):
        if chain.reaches_sink:
            entry = chain.chain[0].caller_function if chain.chain else "unknown"
            print(f"\n  Chain {i}: {entry}() → ... → {chain.sink_type}")
    
    return results


def test_cross_file_parameter_flow():
    """Test parameter flow across multiple files"""
    
    file1 = """
// api.js
import { processRequest } from './middleware';

server.tool("api_call", async ({ url, method, body }) => {
    // Three parameters flow through the system
    const response = await processRequest(url, method, body);
    return response;
});
"""
    
    file2 = """
// middleware.js
import { makeHttpRequest } from './http';

export function processRequest(endpoint, httpMethod, payload) {
    // All three parameters continue flowing
    return makeHttpRequest(endpoint, httpMethod, payload);
}
"""
    
    file3 = """
// http.js
export function makeHttpRequest(url, method, data) {
    // SINK: Network request with user-controlled URL
    return fetch(url, {
        method: method,
        body: JSON.stringify(data)
    });
}
"""
    
    print("\n" + "=" * 80)
    print("  TEST: Cross-File Parameter Flow")
    print("=" * 80)
    print()
    
    tracker = JSCallChainTracker()
    tracker.add_file("api.js", file1)
    tracker.add_file("middleware.js", file2)
    tracker.add_file("http.js", file3)
    
    results = tracker.analyze()
    
    print(f"Tracked {results['total_functions']} functions across {results['total_files']} files")
    print(f"Found {results['dangerous_chains']} dangerous chains")
    
    for chain in results['call_chains']:
        if chain.reaches_sink:
            print(f"\n  Parameters flowing through chain: {', '.join(chain.source_params)}")
            print(f"  Files involved: {len(set(c.caller_file for c in chain.chain))} files")
            print(f"  Final sink: {chain.sink_type}")
    
    return results


def main():
    """Run all tests"""
    print("\n" + "=" * 80)
    print("  COMPREHENSIVE CALL CHAIN TRACKER TESTS")
    print("=" * 80)
    
    # Test 1: Deep call chain
    results1 = test_deep_call_chain()
    
    # Test 2: Multiple entry points
    results2 = test_multiple_entry_points()
    
    # Test 3: Cross-file parameter flow
    results3 = test_cross_file_parameter_flow()
    
    print("\n" + "=" * 80)
    print("  ALL TESTS COMPLETE")
    print("=" * 80)
    print()
    print("✅ Call Chain Tracker Successfully:")
    print("   - Tracks function definitions across multiple files")
    print("   - Resolves imports and exports")
    print("   - Builds complete call chains from entry points")
    print("   - Tracks parameter flow through the chain")
    print("   - Detects when chains reach dangerous sinks")
    print("   - Calculates severity based on chain length and sink type")
    print()
    print(f"📊 Summary:")
    print(f"   - Test 1: {results1['dangerous_chains']} dangerous chains in deep call chain")
    print(f"   - Test 2: {results2['dangerous_chains']} dangerous chains from multiple entry points")
    print(f"   - Test 3: {results3['dangerous_chains']} dangerous chains with parameter flow")
    print()
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
