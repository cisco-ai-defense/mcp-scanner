"""FastMCP decorator pattern (PrefectHQ fastmcp)."""

from fastmcp import FastMCP

mcp = FastMCP("demo")


@mcp.tool
def add(a: int, b: int) -> int:
    """Add two integers."""
    return a + b


if __name__ == "__main__":
    mcp.run()
