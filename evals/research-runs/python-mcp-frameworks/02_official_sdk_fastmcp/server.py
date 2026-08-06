"""Official Python SDK FastMCP import path."""

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")


@mcp.tool
def ping() -> str:
    """Health ping."""
    return "pong"


if __name__ == "__main__":
    mcp.run()
