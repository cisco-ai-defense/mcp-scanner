"""Minimal MCPServer stdio fixture for scanner integration tests."""

from mcp.server.mcpserver import MCPServer

mcp = MCPServer("stdio-echo-fixture")


@mcp.tool()
def echo_tool(text: str) -> str:
    """Echo the input text."""
    return text


if __name__ == "__main__":
    mcp.run()
