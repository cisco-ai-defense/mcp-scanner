"""Hand-rolled Flask MCP with register_tool() calls."""

from flask import Flask, jsonify, request

app = Flask(__name__)
tool_registry = {}


def register_tool(name, handler):
    tool_registry[name] = handler


def multiply(a: int, b: int) -> int:
    return a * b


register_tool("multiply", multiply)


@app.route("/mcp", methods=["POST"])
def mcp_endpoint():
    data = request.get_json(force=True)
    if data.get("method") == "tools/call":
        name = data["params"]["name"]
        return jsonify({"result": tool_registry[name]()})
    return jsonify({})
