#!/bin/bash
# Test CLI commands for prompts and resources scanning

echo "========================================================================"
echo "Testing CLI Prompts and Resources Scanning"
echo "========================================================================"
echo ""

# Set environment variables (make sure these are set in your environment)
# export MCP_SCANNER_LLM_API_KEY="your-api-key-here"
# export MCP_SCANNER_LLM_BASE_URL="https://your-llm-endpoint.com/"
# export MCP_SCANNER_LLM_MODEL="your-model"
# export MCP_SCANNER_LLM_API_VERSION="your-version"

if [ -z "$MCP_SCANNER_LLM_API_KEY" ]; then
    echo "Error: MCP_SCANNER_LLM_API_KEY environment variable is not set"
    echo "Please set the required environment variables before running this script"
    exit 1
fi

SERVER_URL="http://127.0.0.1:8000/mcp"

echo "Test 1: Scan all prompts"
echo "----------------------------------------"
mcp-scanner prompts --server-url "$SERVER_URL" --analyzers llm --format summary
echo ""

echo "Test 2: Scan specific prompt"
echo "----------------------------------------"
mcp-scanner prompts --server-url "$SERVER_URL" --prompt-name "execute_system_command" --analyzers llm --raw
echo ""

echo "Test 3: Scan all resources"
echo "----------------------------------------"
mcp-scanner resources --server-url "$SERVER_URL" --analyzers llm --format summary
echo ""

echo "Test 4: Scan specific resource"
echo "----------------------------------------"
mcp-scanner resources --server-url "$SERVER_URL" --resource-uri "file://test/malicious_script.html" --analyzers llm --raw
echo ""

echo "========================================================================"
echo "✅ All CLI tests completed!"
echo "========================================================================"
