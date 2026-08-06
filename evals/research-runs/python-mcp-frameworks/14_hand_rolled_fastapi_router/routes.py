"""Hand-rolled FastAPI APIRouter with tool_handlers + match dispatch."""

from fastapi import APIRouter, Request

router = APIRouter()


def echo(message: str) -> str:
    return message


tool_handlers = {
    "echo": echo,
}


@router.post("/mcp")
async def mcp_endpoint(request: Request):
    body = await request.json()
    match body.get("method"):
        case "tools/list":
            return {"tools": []}
        case "tools/call":
            name = body["params"]["name"]
            return tool_handlers[name](**body["params"].get("arguments", {}))
    return {}
