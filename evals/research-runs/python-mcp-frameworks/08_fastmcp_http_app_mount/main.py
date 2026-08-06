"""FastMCP http_app mounted on FastAPI."""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastmcp import FastMCP

mcp = FastMCP("demo")


@mcp.tool
def greet(name: str) -> str:
    return f"hello {name}"


mcp_app = mcp.http_app(path="/mcp")


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with mcp_app.lifespan(app):
        yield


app = FastAPI(lifespan=lifespan)
app.mount("/mcp-server", mcp_app)


@app.get("/health")
def health():
    return {"ok": True}
