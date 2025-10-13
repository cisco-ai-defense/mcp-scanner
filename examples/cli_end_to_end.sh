#!/bin/bash
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

# End-to-end CLI test for MCP Scanner - Tools, Prompts, and Resources

set -e  # Exit on error

echo "================================================================================"
echo "🚀 MCP SCANNER - CLI END-TO-END TEST SUITE"
echo "================================================================================"
echo ""
echo "⚠️  Prerequisites:"
echo "   1. Start the test HTTP server in another terminal:"
echo "      python examples/prompts/http_prompt_server.py"
echo "   2. Server should be running on http://127.0.0.1:8000/mcp"
echo ""
echo "================================================================================"
echo ""

# Check if server is running
echo "🔍 Checking if test server is running..."
if ! curl -s http://127.0.0.1:8000/mcp > /dev/null 2>&1; then
    echo "❌ Test server is not running!"
    echo "   Please start it with: python examples/prompts/http_prompt_server.py"
    exit 1
fi
echo "✅ Test server is running"
echo ""

SERVER_URL="http://127.0.0.1:8000/mcp"
PASSED=0
FAILED=0

# Function to run a test
run_test() {
    local test_name="$1"
    local command="$2"

    echo "================================================================================"
    echo "TEST: $test_name"
    echo "================================================================================"
    echo "Command: $command"
    echo ""

    if eval "$command"; then
        echo ""
        echo "✅ PASSED: $test_name"
        ((PASSED++))
    else
        echo ""
        echo "❌ FAILED: $test_name"
        ((FAILED++))
    fi
    echo ""
}

# Test 1: Scan all tools with summary format
run_test "Tool Scanning - Summary Format" \
    "mcp-scanner --analyzers yara --format summary remote --server-url $SERVER_URL"

# Test 2: Scan all tools with detailed format
run_test "Tool Scanning - Detailed Format" \
    "mcp-scanner --analyzers yara --detailed remote --server-url $SERVER_URL"

# Test 3: Scan all tools with table format
run_test "Tool Scanning - Table Format" \
    "mcp-scanner --analyzers yara --format table remote --server-url $SERVER_URL"

# Test 4: Scan all tools with raw JSON format
run_test "Tool Scanning - Raw JSON Format" \
    "mcp-scanner --analyzers yara --raw remote --server-url $SERVER_URL"

# Test 5: Scan all prompts with summary format
run_test "Prompt Scanning - Summary Format" \
    "mcp-scanner --analyzers yara --format summary prompts --server-url $SERVER_URL"

# Test 6: Scan all prompts with detailed format
run_test "Prompt Scanning - Detailed Format" \
    "mcp-scanner --analyzers yara --detailed prompts --server-url $SERVER_URL"

# Test 7: Scan all prompts with table format
run_test "Prompt Scanning - Table Format" \
    "mcp-scanner --analyzers yara --format table prompts --server-url $SERVER_URL"

# Test 8: Scan all prompts with raw JSON format
run_test "Prompt Scanning - Raw JSON Format" \
    "mcp-scanner --analyzers yara --raw prompts --server-url $SERVER_URL"

# Test 9: Scan specific prompt
run_test "Prompt Scanning - Specific Prompt (greet_user)" \
    "mcp-scanner --analyzers yara prompts --server-url $SERVER_URL --prompt-name greet_user"

# Test 10: Scan specific prompt (malicious)
run_test "Prompt Scanning - Specific Prompt (execute_system_command)" \
    "mcp-scanner --analyzers yara prompts --server-url $SERVER_URL --prompt-name execute_system_command"

# Test 11: Scan all resources with summary format
run_test "Resource Scanning - Summary Format" \
    "mcp-scanner --analyzers yara --format summary resources --server-url $SERVER_URL"

# Test 12: Scan all resources with detailed format
run_test "Resource Scanning - Detailed Format" \
    "mcp-scanner --analyzers yara --detailed resources --server-url $SERVER_URL"

# Test 13: Scan all resources with table format
run_test "Resource Scanning - Table Format" \
    "mcp-scanner --analyzers yara --format table resources --server-url $SERVER_URL"

# Test 14: Scan all resources with raw JSON format
run_test "Resource Scanning - Raw JSON Format" \
    "mcp-scanner --analyzers yara --raw resources --server-url $SERVER_URL"

# Test 15: Scan specific resource
run_test "Resource Scanning - Specific Resource (safe_file.txt)" \
    "mcp-scanner --analyzers yara resources --server-url $SERVER_URL --resource-uri 'file://test/safe_file.txt'"

# Test 16: Scan specific resource (malicious)
run_test "Resource Scanning - Specific Resource (malicious_script.html)" \
    "mcp-scanner --analyzers yara resources --server-url $SERVER_URL --resource-uri 'file://test/malicious_script.html'"

# Test 17: Scan resources with MIME type filtering
run_test "Resource Scanning - MIME Type Filtering (text/plain only)" \
    "mcp-scanner --analyzers yara resources --server-url $SERVER_URL --mime-types 'text/plain'"

# Test 18: Scan resources with multiple MIME types
run_test "Resource Scanning - Multiple MIME Types" \
    "mcp-scanner --analyzers yara resources --server-url $SERVER_URL --mime-types 'text/plain,text/html'"

# Summary
echo "================================================================================"
echo "📊 TEST SUMMARY"
echo "================================================================================"
echo ""
TOTAL=$((PASSED + FAILED))
echo "Total Tests: $TOTAL"
echo "✅ Passed: $PASSED"
echo "❌ Failed: $FAILED"
echo ""

if [ $FAILED -eq 0 ]; then
    echo "🎉 All CLI tests passed successfully!"
    echo ""
    exit 0
else
    echo "⚠️  Some tests failed. Please review the output above."
    echo ""
    exit 1
fi
