"""Tadata fastapi_mcp: expose FastAPI routes as MCP tools via operation_id."""

from fastapi import FastAPI
from fastapi_mcp import FastApiMCP

app = FastAPI()


@app.get("/items", operation_id="list_items")
def list_items():
    """List all items."""
    return []


@app.post("/items", operation_id="create_item")
async def create_item():
    """Create an item."""
    return {}


mcp = FastApiMCP(app)
mcp.mount_http()
