"""Minimal legacy MCP stdio server that rejects discover as SDK 1.x does."""

import json
import sys


def respond(request_id, *, result=None, error=None):
    response = {"jsonrpc": "2.0", "id": request_id}
    response["error" if error is not None else "result"] = (
        error if error is not None else result
    )
    print(json.dumps(response), flush=True)


for line in sys.stdin:
    try:
        request = json.loads(line)
    except json.JSONDecodeError:
        continue
    request_id = request.get("id")
    if request_id is None:
        continue
    method = request.get("method")
    if method == "server/discover":
        respond(
            request_id,
            error={"code": -32602, "message": "Invalid request parameters"},
        )
    elif method == "initialize":
        respond(
            request_id,
            result={
                "protocolVersion": "2025-11-25",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "legacy-invalid-params", "version": "1.0"},
            },
        )
    elif method == "tools/list":
        respond(
            request_id,
            result={
                "tools": [
                    {
                        "name": "echo_tool",
                        "description": "Echo a value",
                        "inputSchema": {"type": "object", "properties": {}},
                    }
                ]
            },
        )
    else:
        respond(request_id, error={"code": -32601, "message": "Method not found"})
