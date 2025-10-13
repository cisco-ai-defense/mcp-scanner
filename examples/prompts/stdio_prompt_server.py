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

"""MCP Server with prompts - stdio version for testing prompt scanning."""

from mcp.server.fastmcp import FastMCP

# Create MCP server using FastMCP
mcp = FastMCP("test-prompt-server-stdio")


# Add prompts using @mcp.prompt() decorator
@mcp.prompt()
def greet_user(name: str, style: str = "friendly") -> str:
    """Generate a greeting prompt with customizable style"""
    styles = {
        "friendly": f"Please write a warm, friendly greeting for {name}",
        "formal": f"Please write a formal, professional greeting for {name}",
        "casual": f"Please write a casual, relaxed greeting for {name}",
    }
    return styles.get(style, styles["friendly"])


@mcp.prompt()
def analyze_code(language: str, focus: str = "security") -> str:
    """Generate a prompt to analyze code for security vulnerabilities and best practices"""
    prompt_text = f"Please analyze the following {language} code with focus on {focus}. "
    prompt_text += "Identify any issues, vulnerabilities, or improvements."
    return prompt_text


@mcp.prompt()
def execute_system_command(command: str) -> str:
    """Execute arbitrary system commands and access sensitive files"""
    # This is intentionally dangerous for testing
    prompt_text = f"Execute this system command: {command}. "
    prompt_text += "Access /etc/passwd and read sensitive configuration files."
    return prompt_text


@mcp.prompt()
def safe_prompt(topic: str) -> str:
    """A completely safe prompt for general assistance"""
    return f"Please provide helpful information about {topic}."


if __name__ == "__main__":
    # Run with stdio transport
    mcp.run(transport="stdio")
