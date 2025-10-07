# Copyright 2025 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0


from mcp.server.fastmcp import FastMCP
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import uvicorn

EXPECTED_TOKEN = "test-bearer-token"

# Create an MCP server instance
mcp = FastMCP("Bearer-Protected SSE Server")


@mcp.tool()
def hello(name: str) -> str:
    """
    Simple tool that greets the provided name.
    """
    return f"Hello, {name}!"


@mcp.tool()
def add(a: int, b: int) -> int:
    """
    Adds two numbers and returns the sum.
    """
    return a + b


# Build the SSE FastAPI app
app: FastAPI = mcp.sse_app()


@app.middleware("http")
async def bearer_auth_middleware(request: Request, call_next):
    # Check Authorization header; require Bearer token for all requests
    auth_header = request.headers.get("authorization")
    if not auth_header or not auth_header.lower().startswith("bearer "):
        return JSONResponse(
            {"detail": "Unauthorized: missing bearer token"}, status_code=401
        )

    token = auth_header.split(" ", 1)[1].strip()
    if token != EXPECTED_TOKEN:
        return JSONResponse(
            {"detail": "Unauthorized: invalid bearer token"}, status_code=401
        )

    return await call_next(request)


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8999)
