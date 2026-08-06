"""Vanilla FastAPI + official MCPServer streamable HTTP mount."""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from mcp.server import MCPServer

mcp = MCPServer("Notes")


@mcp.tool()
def add_note(text: str) -> str:
    """Save a note."""
    return f"Saved: {text}"


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with mcp.session_manager.run():
        yield


app = FastAPI(lifespan=lifespan)
app.mount("/mcp-server", mcp.streamable_http_app())


@app.get("/health")
def health():
    return {"status": "ok"}
