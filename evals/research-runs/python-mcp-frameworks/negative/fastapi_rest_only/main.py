"""Negative: plain FastAPI REST — should not be detected as MCP."""

from fastapi import FastAPI

app = FastAPI()


@app.get("/items")
def list_items():
    return []


@app.post("/items")
def create_item():
    return {}
