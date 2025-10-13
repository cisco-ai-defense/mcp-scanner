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

# End-to-end API test for MCP Scanner - Tools, Prompts, and Resources

set -e  # Exit on error

echo "================================================================================"
echo "🚀 MCP SCANNER - API END-TO-END TEST SUITE"
echo "================================================================================"
echo ""
echo "⚠️  Prerequisites:"
echo "   1. Start the MCP Scanner API server in another terminal:"
echo "      mcp-scanner-api --port 8001"
echo "   2. Start the test MCP server in another terminal:"
echo "      python examples/test_server_complete.py"
echo "   3. Servers should be running on:"
echo "      - API: http://127.0.0.1:8001"
echo "      - MCP: http://127.0.0.1:8000/mcp"
echo ""
echo "================================================================================"
echo ""

# Check if API server is running
echo "🔍 Checking if API server is running..."
if ! curl -s http://127.0.0.1:8001/health > /dev/null 2>&1; then
    echo "❌ API server is not running!"
    echo "   Please start it with: mcp-scanner-api --port 8001"
    exit 1
fi
echo "✅ API server is running"

# Check if MCP test server is running
echo "🔍 Checking if MCP test server is running..."
if ! curl -s http://127.0.0.1:8000/mcp > /dev/null 2>&1; then
    echo "❌ MCP test server is not running!"
    echo "   Please start it with: python examples/test_server_complete.py"
    exit 1
fi
echo "✅ MCP test server is running"
echo ""

API_URL="http://127.0.0.1:8001"
MCP_URL="http://127.0.0.1:8000/mcp"
PASSED=0
FAILED=0

# Function to run a test
run_test() {
    local test_name="$1"
    local endpoint="$2"
    local data="$3"

    echo "================================================================================"
    echo "TEST: $test_name"
    echo "================================================================================"
    echo "Endpoint: POST $API_URL$endpoint"
    echo ""

    response=$(curl -s -X POST "$API_URL$endpoint" \
        -H "Content-Type: application/json" \
        -d "$data")

    if [ $? -eq 0 ] && [ ! -z "$response" ]; then
        echo "✅ Response received"
        echo "$response" | python -m json.tool 2>/dev/null | head -30 || echo "$response" | head -30
        echo ""
        echo "✅ PASSED: $test_name"
        ((PASSED++))
    else
        echo "❌ FAILED: $test_name"
        ((FAILED++))
    fi
    echo ""
}

# Test 1: Scan all tools
run_test "Tool Scanning - Scan All Tools" \
    "/scan-all-tools" \
    '{
        "server_url": "'"$MCP_URL"'",
        "analyzers": ["yara"]
    }'

# Test 2: Scan specific tool
run_test "Tool Scanning - Scan Specific Tool (add)" \
    "/scan-tool" \
    '{
        "server_url": "'"$MCP_URL"'",
        "tool_name": "add",
        "analyzers": ["yara"]
    }'

# Test 3: Scan specific tool (malicious)
run_test "Tool Scanning - Scan Specific Tool (execute_command)" \
    "/scan-tool" \
    '{
        "server_url": "'"$MCP_URL"'",
        "tool_name": "execute_command",
        "analyzers": ["yara"]
    }'

# Test 4: Scan all prompts
run_test "Prompt Scanning - Scan All Prompts" \
    "/scan-all-prompts" \
    '{
        "server_url": "'"$MCP_URL"'",
        "analyzers": ["yara"]
    }'

# Test 5: Scan specific prompt
run_test "Prompt Scanning - Scan Specific Prompt (greet_user)" \
    "/scan-prompt" \
    '{
        "server_url": "'"$MCP_URL"'",
        "prompt_name": "greet_user",
        "analyzers": ["yara"]
    }'

# Test 6: Scan specific prompt (malicious)
run_test "Prompt Scanning - Scan Specific Prompt (malicious_injection)" \
    "/scan-prompt" \
    '{
        "server_url": "'"$MCP_URL"'",
        "prompt_name": "malicious_injection",
        "analyzers": ["yara"]
    }'

# Test 7: Scan all resources
run_test "Resource Scanning - Scan All Resources" \
    "/scan-all-resources" \
    '{
        "server_url": "'"$MCP_URL"'",
        "analyzers": ["yara"],
        "allowed_mime_types": ["text/plain", "text/html", "application/json"]
    }'

# Test 8: Scan specific resource
run_test "Resource Scanning - Scan Specific Resource (safe_file.txt)" \
    "/scan-resource" \
    '{
        "server_url": "'"$MCP_URL"'",
        "resource_uri": "file://test/safe_file.txt",
        "analyzers": ["yara"]
    }'

# Test 9: Scan specific resource (malicious)
run_test "Resource Scanning - Scan Specific Resource (malicious_script.html)" \
    "/scan-resource" \
    '{
        "server_url": "'"$MCP_URL"'",
        "resource_uri": "file://test/malicious_script.html",
        "analyzers": ["yara"]
    }'

# Test 10: Health check
echo "================================================================================"
echo "TEST: Health Check"
echo "================================================================================"
echo "Endpoint: GET $API_URL/health"
echo ""

health_response=$(curl -s "$API_URL/health")
if [ $? -eq 0 ] && [ ! -z "$health_response" ]; then
    echo "✅ Response received"
    echo "$health_response"
    echo ""
    echo "✅ PASSED: Health Check"
    ((PASSED++))
else
    echo "❌ FAILED: Health Check"
    ((FAILED++))
fi
echo ""

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
    echo "🎉 All API tests passed successfully!"
    echo ""
    exit 0
else
    echo "⚠️  Some tests failed. Please review the output above."
    echo ""
    exit 1
fi
