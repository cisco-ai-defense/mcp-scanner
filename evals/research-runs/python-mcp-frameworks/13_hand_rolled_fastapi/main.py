"""Hand-rolled FastAPI MCP with TOOLS registry."""

from fastapi import FastAPI, Request

app = FastAPI()


async def add_numbers(a: int, b: int) -> int:
    return a + b


async def list_items():
    return []


TOOLS = {
    "add": add_numbers,
    "list_items": list_items,
}


@app.post("/mcp")
async def mcp_endpoint(request: Request):
    body = await request.json()
    method = body.get("method")
    if method == "tools/list":
        return {"jsonrpc": "2.0", "result": {"tools": []}, "id": body.get("id")}
    if method == "tools/call":
        name = body.get("params", {}).get("name")
        handler = TOOLS[name]
        result = await handler(**body.get("params", {}).get("arguments", {}))
        return {"jsonrpc": "2.0", "result": result, "id": body.get("id")}
    return {"jsonrpc": "2.0", "error": {"code": -32601}, "id": body.get("id")}


@app.get("/health")
async def health():
    return {"ok": True}
