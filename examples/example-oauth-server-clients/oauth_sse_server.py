# Copyright 2025 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0

import time
import secrets
from typing import Dict

from fastapi import FastAPI, Request, Depends, HTTPException, status
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from mcp.server.fastmcp import FastMCP
import uvicorn

# ---- Simple In-Memory OAuth Provider (Authorization Code Grant) ----
EXPECTED_CLIENT_ID = "test-client"
EXPECTED_CLIENT_SECRET = "test-secret"
TOKEN_TTL_SECONDS = 3600

AUTH_CODES: Dict[str, Dict] = {}
TOKENS: Dict[str, Dict] = {}


def issue_code(client_id: str, redirect_uri: str, state: str | None):
    code = secrets.token_urlsafe(16)
    AUTH_CODES[code] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": state,
        "issued_at": time.time(),
    }
    return code


def exchange_code(code: str, client_id: str, client_secret: str, redirect_uri: str):
    data = AUTH_CODES.get(code)
    if not data:
        raise HTTPException(status_code=400, detail="invalid_grant")
    if data["client_id"] != client_id or client_id != EXPECTED_CLIENT_ID:
        raise HTTPException(status_code=400, detail="invalid_client")
    if client_secret != EXPECTED_CLIENT_SECRET:
        raise HTTPException(status_code=400, detail="invalid_client")
    if data["redirect_uri"] != redirect_uri:
        raise HTTPException(status_code=400, detail="invalid_grant")

    # Issue access token
    access_token = secrets.token_urlsafe(24)
    TOKENS[access_token] = {
        "client_id": client_id,
        "expires_at": time.time() + TOKEN_TTL_SECONDS,
    }

    # One-time use code
    del AUTH_CODES[code]

    return access_token


def validate_bearer(request: Request):
    auth_header = request.headers.get("authorization")
    if not auth_header or not auth_header.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="missing_token"
        )
    token = auth_header.split(" ", 1)[1].strip()
    token_data = TOKENS.get(token)
    if not token_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid_token"
        )
    if time.time() > token_data["expires_at"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="expired_token"
        )
    return True


# ---- MCP SSE Server with OAuth protection ----

mcp = FastMCP("OAuth-Protected SSE Server")


@mcp.tool()
def hello(name: str) -> str:
    return f"Hello, {name}!"


@mcp.tool()
def add(a: int, b: int) -> int:
    return a + b


app: FastAPI = FastAPI(title="OAuth + MCP SSE")


# OAuth endpoints
@app.get("/.well-known/oauth-authorization-server")
async def oauth_discovery():
    return {
        "issuer": (
            OAUTH_BASE
            if (OAUTH_BASE := "http://127.0.0.1:9001")
            else "http://127.0.0.1:9001"
        ),
        "authorization_endpoint": "http://127.0.0.1:9001/oauth/authorize",
        "token_endpoint": "http://127.0.0.1:9001/oauth/token",
        "registration_endpoint": "http://127.0.0.1:9001/oauth/register",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "token_endpoint_auth_methods_supported": ["client_secret_post"],
        "scopes_supported": ["tools.read"],
    }


@app.post("/oauth/register")
async def oauth_register(request: Request):
    # Minimal dynamic client registration that simply echoes back a fixed client
    body = await request.json()
    redirect_uris = body.get("redirect_uris") or []
    if not redirect_uris:
        return JSONResponse({"error": "invalid_client_metadata"}, status_code=400)
    return {
        "client_id": EXPECTED_CLIENT_ID,
        "client_secret": EXPECTED_CLIENT_SECRET,
        "redirect_uris": redirect_uris,
        "token_endpoint_auth_method": "client_secret_post",
    }


@app.get("/oauth/authorize")
async def oauth_authorize(
    response_type: str,
    client_id: str,
    redirect_uri: str,
    state: str | None = None,
    scope: str | None = None,
):
    if response_type != "code":
        raise HTTPException(status_code=400, detail="unsupported_response_type")
    if client_id != EXPECTED_CLIENT_ID:
        raise HTTPException(status_code=400, detail="unauthorized_client")

    code = issue_code(client_id, redirect_uri, state)
    redirect_to = f"{redirect_uri}?code={code}"
    if state:
        redirect_to += f"&state={state}"
    return RedirectResponse(url=redirect_to, status_code=302)


@app.post("/oauth/token")
async def oauth_token(request: Request):
    form = await request.form()
    grant_type = form.get("grant_type")
    code = form.get("code")
    redirect_uri = form.get("redirect_uri")
    client_id = form.get("client_id")
    client_secret = form.get("client_secret")

    if grant_type != "authorization_code":
        raise HTTPException(status_code=400, detail="unsupported_grant_type")
    if not all([code, redirect_uri, client_id, client_secret]):
        raise HTTPException(status_code=400, detail="invalid_request")

    access_token = exchange_code(code, client_id, client_secret, redirect_uri)
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": TOKEN_TTL_SECONDS,
    }


# Mount MCP SSE app and protect it with auth middleware
mcp_app = mcp.sse_app()


@app.middleware("http")
async def oauth_protect_middleware(request: Request, call_next):
    # Allow OAuth endpoints
    if request.url.path.startswith("/oauth/"):
        return await call_next(request)
    # Protect SSE endpoints and MCP traffic
    if request.url.path.startswith("/sse"):
        try:
            validate_bearer(request)
        except HTTPException as he:
            return JSONResponse({"detail": he.detail}, status_code=he.status_code)
    return await call_next(request)


# Include MCP routes under root
app.mount("/", mcp_app)


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=9001)
