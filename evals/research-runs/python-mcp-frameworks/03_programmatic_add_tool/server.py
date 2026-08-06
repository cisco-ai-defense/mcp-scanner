"""Programmatic tool registration via mcp.add_tool."""

from fastmcp import FastMCP


def multiply(a: int, b: int) -> int:
    """Multiply two integers."""
    return a * b


mcp = FastMCP("demo")
mcp.add_tool(multiply)


if __name__ == "__main__":
    mcp.run()
