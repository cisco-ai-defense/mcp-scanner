"""Tadata fastapi_mcp on APIRouter."""

from fastapi import APIRouter
from fastapi_mcp import FastApiMCP

router = APIRouter()


@router.get("/health", operation_id="health_check")
def health():
    return {"ok": True}


mcp = FastApiMCP(router)
