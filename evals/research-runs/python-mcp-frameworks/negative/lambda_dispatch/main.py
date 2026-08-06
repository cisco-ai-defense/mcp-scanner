"""Negative: lambda dispatch table — known coverage gap."""

from fastapi import FastAPI, Request

app = FastAPI()


def multiply(a: int, b: int) -> int:
    return a * b


MCP_METHODS = {
    "tools/list": lambda params: {"tools": [{"name": "multiply"}]},
    "tools/call": lambda params: multiply(**params.get("arguments", {})),
}


@app.post("/mcp")
async def mcp_rpc(request: Request):
    body = await request.json()
    handler = MCP_METHODS.get(body.get("method"))
    if handler is None:
        return {"error": {"code": -32601}}
    return {"result": handler(body.get("params", {}))}
