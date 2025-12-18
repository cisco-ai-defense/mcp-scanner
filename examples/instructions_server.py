#!/usr/bin/env python3
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

"""
Example MCP Server with Instructions Field

This example demonstrates how to create an MCP server that provides
instructions in the InitializeResult. The instructions field can be
scanned for security issues using the MCP Scanner.

Usage:
    python examples/instructions_server.py

The server will start on http://127.0.0.1:8001/mcp
"""

from mcp.server.fastmcp import FastMCP

# Create MCP server with instructions
mcp = FastMCP(
    "test-instructions-server",
    instructions="""This is a test MCP server for scanning instructions.

Usage Guidelines:
- Use the 'add' tool for safe mathematical operations
- The 'execute_command' tool is dangerous and should be used with caution
- Always validate input before processing
- Contact admin@example.com for support

Security Note: This server includes both safe and potentially dangerous tools.
Please review the tool descriptions carefully before use."""
)


@mcp.tool()
def add(a: int, b: int) -> int:
    """Add two numbers together - Safe tool"""
    return a + b


@mcp.tool()
def execute_command(command: str) -> str:
    """Execute arbitrary system commands - DANGEROUS tool"""
    import subprocess
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout


@mcp.tool()
def safe_calculator(operation: str, num1: float, num2: float) -> float:
    """Perform safe mathematical operations"""
    operations = {
        'add': lambda x, y: x + y,
        'subtract': lambda x, y: x - y,
        'multiply': lambda x, y: x * y,
        'divide': lambda x, y: x / y if y != 0 else 0
    }
    return operations.get(operation, lambda x, y: 0)(num1, num2)


if __name__ == "__main__":
    import uvicorn

    # Build the Streamable FastAPI app
    app = mcp.streamable_http_app()

    print("=" * 80)
    print("🚀 MCP Test Server with Instructions")
    print("=" * 80)
    print("\nServer URL: http://127.0.0.1:8001/mcp")
    print("\n📋 Server Instructions:")
    print(mcp.instructions if hasattr(mcp, 'instructions') else "Instructions configured")
    print("\n📦 Available Tools (3):")
    print("  ✅ add - Safe mathematical addition")
    print("  ⚠️  execute_command - MALICIOUS: Execute system commands")
    print("  ✅ safe_calculator - Safe calculator operations")
    print("\n" + "=" * 80)
    print("Press Ctrl+C to stop")
    print("=" * 80)
    print()

    uvicorn.run(app, host="127.0.0.1", port=8001)
