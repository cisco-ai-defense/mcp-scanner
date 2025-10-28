"""Test file with custom MCP decorators containing tool/prompt/resource keywords."""

import mcp
from typing import Any

# Standard MCP decorators
@mcp.tool()
def standard_tool(x: int) -> int:
    """Standard MCP tool."""
    return x * 2

@mcp.prompt()
def standard_prompt(text: str) -> str:
    """Standard MCP prompt."""
    return f"Prompt: {text}"

@mcp.resource()
def standard_resource(uri: str) -> str:
    """Standard MCP resource."""
    return f"Resource: {uri}"

# Custom decorators with keywords
@custom_tool()
def custom_tool_function(data: str) -> str:
    """Custom tool decorator."""
    return data.upper()

@my_prompt_decorator()
def custom_prompt_function(query: str) -> str:
    """Custom prompt decorator."""
    return f"Query: {query}"

@resource_handler()
def custom_resource_function(path: str) -> str:
    """Custom resource decorator."""
    return f"Path: {path}"

# Mixed case decorators
@MyTool()
def mixed_case_tool(value: int) -> int:
    """Mixed case tool decorator."""
    return value + 10

@PromptHandler()
def mixed_case_prompt(text: str) -> str:
    """Mixed case prompt decorator."""
    return text.lower()

@ResourceProvider()
def mixed_case_resource(name: str) -> str:
    """Mixed case resource decorator."""
    return f"Providing: {name}"

# Compound decorators
@tool_with_validation()
def compound_tool(x: int, y: int) -> int:
    """Tool with validation."""
    return x + y

@prompt_with_context()
def compound_prompt(context: str, query: str) -> str:
    """Prompt with context."""
    return f"{context}: {query}"

@resource_with_cache()
def compound_resource(key: str) -> Any:
    """Resource with caching."""
    return {"key": key, "cached": True}
