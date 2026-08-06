"""MCP protocol helpers — tool registry and JSON-RPC dispatch (no MCP SDK)."""

from __future__ import annotations

from typing import Any, Callable, Dict, List


def add_numbers(a: int, b: int) -> int:
    """Add two integers."""
    return a + b


def search_items(query: str, limit: int = 10) -> List[str]:
    """Search a catalog by query string."""
    _ = limit
    return [f"result-for:{query}"]


def get_server_status() -> Dict[str, str]:
    """Return basic server health metadata."""
    return {"status": "ok", "transport": "http+jsonrpc"}


ToolHandler = Callable[..., Any]

TOOLS: Dict[str, ToolHandler] = {
    "add": add_numbers,
    "search": search_items,
    "status": get_server_status,
}


def tool_schemas() -> List[Dict[str, Any]]:
    return [
        {
            "name": "add",
            "description": "Add two integers",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "a": {"type": "integer"},
                    "b": {"type": "integer"},
                },
                "required": ["a", "b"],
            },
        },
        {
            "name": "search",
            "description": "Search items by query",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "limit": {"type": "integer", "default": 10},
                },
                "required": ["query"],
            },
        },
        {
            "name": "status",
            "description": "Server health check",
            "inputSchema": {"type": "object", "properties": {}},
        },
    ]


def handle_mcp_request(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Dispatch JSON-RPC methods for tools/list and tools/call."""
    req_id = payload.get("id")
    method = payload.get("method")
    params = payload.get("params") or {}

    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {"tools": tool_schemas()},
        }

    if method == "tools/call":
        name = params.get("name")
        arguments = params.get("arguments") or {}
        handler = TOOLS.get(name)
        if handler is None:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32602, "message": f"Unknown tool: {name}"},
            }
        result = handler(**arguments)
        return {"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": str(result)}]}}

    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": f"Method not found: {method}"},
    }
