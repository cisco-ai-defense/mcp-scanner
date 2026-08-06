"""Python SDK v2 MCPServer with @app.tool decorator."""

from mcp.server.mcpserver import MCPServer

app = MCPServer("demo")


@app.tool
def greet(name: str) -> str:
    """Greet by name."""
    return f"hello {name}"


if __name__ == "__main__":
    app.run()
