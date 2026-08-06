"""Negative: plain Flask REST — should not be detected as MCP."""

from flask import Flask

app = Flask(__name__)


@app.route("/items")
def list_items():
    return []


def helper():
    return None
