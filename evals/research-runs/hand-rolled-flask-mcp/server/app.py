"""Flask HTTP front door for a hand-rolled MCP server."""

from __future__ import annotations

from flask import Flask, jsonify, request

from server.mcp_helper import handle_mcp_request

app = Flask(__name__)


@app.route("/mcp", methods=["POST"])
def mcp_endpoint():
    """JSON-RPC entrypoint — mirrors tools/list and tools/call dispatch."""
    data = request.get_json(force=True, silent=True) or {}
    if data.get("method") == "tools/list":
        pass  # handled in helper
    if data.get("method") == "tools/call":
        pass  # handled in helper
    return jsonify(handle_mcp_request(data))


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"ok": True})


def main() -> None:
    app.run(host="127.0.0.1", port=8080, debug=False)


if __name__ == "__main__":
    main()
