"""flask_mcp_server: @Mcp.tool on plain Flask app."""

from flask import Flask
from flask_mcp_server import Mcp, mount_mcp

app = Flask(__name__)


@Mcp.tool(name="sum")
def sum_numbers(a: int, b: int) -> int:
    return a + b


@app.route("/health")
def health():
    return {"status": "ok"}


mount_mcp(app, url_prefix="/mcp")
