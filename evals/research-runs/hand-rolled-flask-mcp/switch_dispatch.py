"""Alternate DIY MCP pattern: inline schemas + name switch (no TOOLS dict).

This style appears in production repos (e.g. split helper modules) but is
not yet extracted by mcp-scanner static analysis — included as a gap demo.
"""

from __future__ import annotations

from typing import Any, Dict, List

from flask import Flask, jsonify, request

app = Flask(__name__)


def echo_message(message: str) -> str:
    return message


def reverse_text(text: str) -> str:
    return text[::-1]


@app.route("/mcp", methods=["POST"])
def mcp_endpoint():
    data = request.get_json(force=True, silent=True) or {}
    method = data.get("method")
    req_id = data.get("id")

    if method == "tools/list":
        tools = [
            {
                "name": "echo",
                "description": "Echo a message",
                "inputSchema": {
                    "type": "object",
                    "properties": {"message": {"type": "string"}},
                    "required": ["message"],
                },
            },
            {
                "name": "reverse",
                "description": "Reverse input text",
                "inputSchema": {
                    "type": "object",
                    "properties": {"text": {"type": "string"}},
                    "required": ["text"],
                },
            },
        ]
        return jsonify({"jsonrpc": "2.0", "id": req_id, "result": {"tools": tools}})

    if method == "tools/call":
        name = (data.get("params") or {}).get("name")
        arguments = (data.get("params") or {}).get("arguments") or {}
        if name == "echo":
            result = echo_message(**arguments)
        elif name == "reverse":
            result = reverse_text(**arguments)
        else:
            return jsonify(
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32602, "message": f"Unknown tool: {name}"},
                }
            )
        return jsonify(
            {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"content": [{"type": "text", "text": str(result)}]},
            }
        )

    return jsonify(
        {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": "Method not found"},
        }
    )


if __name__ == "__main__":
    app.run(port=8081)
