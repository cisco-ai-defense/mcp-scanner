"""Hand-rolled Flask MCP with TOOLS registry."""

from flask import Flask, jsonify, request

app = Flask(__name__)


def add_numbers(a: int, b: int) -> int:
    return a + b


def search_items(query: str):
    return []


TOOLS = {
    "add": add_numbers,
    "search": search_items,
}


@app.route("/mcp", methods=["POST"])
def mcp_endpoint():
    data = request.get_json(force=True)
    method = data.get("method")
    if method == "tools/list":
        return jsonify({"jsonrpc": "2.0", "result": {"tools": []}, "id": data.get("id")})
    if method == "tools/call":
        name = data.get("params", {}).get("name")
        handler = TOOLS[name]
        return jsonify({"jsonrpc": "2.0", "result": handler(**{}), "id": data.get("id")})
    return jsonify({"jsonrpc": "2.0", "error": {"code": -32601}, "id": data.get("id")})
