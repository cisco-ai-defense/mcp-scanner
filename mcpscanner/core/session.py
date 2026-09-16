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

"""MCP transport and session management.

Connecting to an MCP server -- transport negotiation, OAuth, stdio process
launch, teardown -- is a separate concern from deciding what to scan, and it
was the part of ``Scanner`` hardest to exercise in isolation: these six
functions touched no scanner state at all, yet reaching them meant
constructing a full ``Scanner`` with every analyzer instantiated.

``Scanner`` keeps thin delegating wrappers so existing callers and test
patches against its private methods continue to work.
"""

import asyncio
import os
import sys
import warnings
import logging as stdlib_logging
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Dict, Iterator, Optional, Tuple

from mcp import StdioServerParameters
from mcp.client.session import ClientSession
from mcp.client.sse import sse_client
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client, create_mcp_http_client

from ..utils.command_utils import (
    build_env_for_expansion,
    decide_windows_semantics,
    normalize_and_expand_command_args,
    resolve_executable_path,
    split_embedded_args,
)
from ..utils.logging_config import get_logger
from ..utils.proxy_relay import is_hybrid_connector_id, prepare_mcp_dial
from .auth import Auth, AuthType, create_oauth_provider_from_auth
from .exceptions import (
    MCPAuthenticationError,
    MCPConnectionError,
    MCPServerNotFoundError,
)
from .mcp_models import StdioServer

logger = get_logger(__name__)


def is_missing_capability_error(error: Exception) -> bool:
    """Return True when the server reports a capability is unavailable.

    Covers three real-world shapes of "this method isn't implemented":

    1. Spec-compliant JSON-RPC ``-32601`` ("Method not found").
    2. Free-form message tokens (some servers return ``-32603`` with a
       ``"unsupported"``-style message).
    3. The MCP Python SDK's synthetic ``32600`` + ``"Session terminated"``
       that ``mcp/client/streamable_http.py`` emits when the server
       replies to a JSON-RPC POST with a plain HTTP 404. Many real-world
       MCP servers (BigQuery, several Google APIs, some Cloudflare/GitHub
       endpoints) return 404 for unimplemented ``resources/list`` or
       ``prompts/list`` instead of a proper ``-32601`` error, and the SDK
       relabels that as a session-terminated error. Treat the synthetic
       shape as a missing-capability signal so callers can return ``[]``
       instead of bubbling a misleading 500.
    """
    messages = [str(error)]
    code = getattr(error, "code", None)

    rpc_error = getattr(error, "error", None)
    if hasattr(rpc_error, "code") and getattr(rpc_error, "code") is not None:
        code = code or rpc_error.code
        rpc_message = getattr(rpc_error, "message", None)
        if rpc_message:
            messages.append(str(rpc_message))
    elif isinstance(rpc_error, dict):
        code = code or rpc_error.get("code")
        rpc_message = rpc_error.get("message")
        if rpc_message:
            messages.append(str(rpc_message))

    combined_message = " ".join(m for m in messages if m).lower()

    if code == -32601:
        return True

    # SDK-synthetic shape for "server returned HTTP 404 for this method".
    # We require BOTH the code and the canonical message so we don't
    # silently swallow real mid-session terminations (which can use the
    # same 32600 code with different messages).
    if code == 32600 and "session terminated" in combined_message:
        return True

    tokens = (
        "method not found",
        "methodnotfound",
        "not implemented",
        "unsupported",
        "does not have",
        "doesn't have",
    )
    return any(token in combined_message for token in tokens)


def server_supports_capability(
    session: Any, capability: str
) -> Optional[bool]:
    """Check whether the server advertised support for a capability.

    Reads the ``InitializeResult.capabilities`` that ``_get_mcp_session``
    stashes on the session as ``_init_result``. Returns:

    * ``True``  — server explicitly advertised this capability.
    * ``False`` — server explicitly omitted it; we can short-circuit.
    * ``None``  — we don't have init info; caller must fall back to the
                 try/except path on the actual JSON-RPC call.
    """
    init_result = getattr(session, "_init_result", None)
    if init_result is None:
        return None
    capabilities = getattr(init_result, "capabilities", None)
    if capabilities is None:
        return None
    # ServerCapabilities is a pydantic model; missing optional fields
    # default to None. A non-None object (even if empty) signals the
    # server advertised the capability.
    return getattr(capabilities, capability, None) is not None


def check_http_error_in_logs(msg: str) -> Optional[int]:
    """Check if a log message contains an HTTP error status code.

    Args:
        msg: Log message to check

    Returns:
        HTTP status code if found (401, 403, 404), None otherwise
    """
    if "401" in msg or "Unauthorized" in msg:
        return 401
    elif "403" in msg or "Forbidden" in msg:
        return 403
    elif "404" in msg or "Not Found" in msg:
        return 404
    return None


async def close_mcp_session(client_context, session):
    """Close MCP session and client context safely.

    Args:
        client_context: The MCP client context
        session: The MCP session
    """
    # Close session first
    if session:
        try:
            await session.__aexit__(None, None, None)
        except (
            asyncio.CancelledError,
            GeneratorExit,
            RuntimeError,
            BaseExceptionGroup,
        ):
            # Suppress cleanup errors from MCP library bugs
            # These are expected when connection fails
            pass
        except Exception as e:
            # Log unexpected errors
            if "cancel scope" not in str(e) and "TaskGroup" not in str(e):
                logger.warning(f"Error closing session: {e}")

    # Close client context
    if client_context:
        try:
            # Ensure we're in the same task context for cleanup
            await client_context.__aexit__(None, None, None)
        except (
            asyncio.CancelledError,
            GeneratorExit,
            RuntimeError,
            BaseExceptionGroup,
        ):
            # Suppress cleanup errors from MCP library bugs
            # These are expected when connection fails
            pass
        except Exception as e:
            # Log unexpected errors
            if "cancel scope" not in str(e) and "TaskGroup" not in str(e):
                logger.warning(f"Error closing client context: {e}")

        # Explicitly close the httpx.AsyncClient we created, in case the
        # MCP library's own cleanup failed (e.g. session termination
        # DELETE returned 404 and the task group teardown left the
        # client unclosed).
        httpx_client = getattr(client_context, "_httpx_client", None)
        if httpx_client and not httpx_client.is_closed:
            try:
                await httpx_client.aclose()
            except Exception:
                pass


@dataclass
class _HttpStatusProbe:
    """The HTTP status code httpx logged during a connection attempt."""

    code: Optional[int] = None


@contextmanager
def _capture_http_status() -> Iterator[_HttpStatusProbe]:
    """Watch httpx's log output for the status code behind a failed connect.

    The MCP library surfaces an HTTP 401/403/404 as a cancelled task or an
    ExceptionGroup, which loses the code. httpx logs it one line earlier, so
    reading that line is the only way to tell "needs authentication" apart
    from "server is unreachable".
    """
    probe = _HttpStatusProbe()
    httpx_logger = stdlib_logging.getLogger("httpx")
    original_level = httpx_logger.level
    original_propagate = httpx_logger.propagate

    class StatusCodeCapture(stdlib_logging.Handler):
        def __init__(self):
            super().__init__(level=stdlib_logging.INFO)

        def emit(self, record):
            probe.code = check_http_error_in_logs(record.getMessage()) or probe.code

    handler = StatusCodeCapture()
    handler._check_http_error_in_logs = check_http_error_in_logs
    httpx_logger.addHandler(handler)

    # Raise the level so the lines we need are emitted at all, and stop them
    # propagating so raising it does not spray httpx output onto the console.
    if (
        original_level > stdlib_logging.INFO
        or original_level == stdlib_logging.NOTSET
    ):
        httpx_logger.setLevel(stdlib_logging.INFO)
        httpx_logger.propagate = False

    try:
        yield probe
    finally:
        httpx_logger.removeHandler(handler)
        httpx_logger.setLevel(original_level)
        httpx_logger.propagate = original_propagate


def _auth_headers(
    auth: Optional[Auth], server_url: str
) -> Tuple[Optional[Any], Dict[str, str]]:
    """Turn an Auth configuration into an OAuth provider and request headers.

    Returns ``(oauth_provider, extra_headers)``; both are empty when no auth
    was configured, which means connecting anonymously.
    """
    if auth is None:
        logger.debug(
            f'No explicit auth provided, connecting without authentication: server="{server_url}"'
        )
        return None, {}

    oauth_provider = None
    extra_headers: Dict[str, str] = {}

    if auth.type == AuthType.OAUTH:
        logger.debug(
            f'Using explicit OAuth authentication for MCP server: server="{server_url}"'
        )
        oauth_provider = create_oauth_provider_from_auth(auth, server_url)
    elif auth.type == AuthType.BEARER:
        if not getattr(auth, "bearer_token", None):
            raise ValueError(
                "Bearer authentication selected but no bearer_token provided"
            )
        extra_headers["Authorization"] = f"Bearer {auth.bearer_token}"
        logger.debug(
            f'Using explicit Bearer authentication for MCP server: server="{server_url}"'
        )
    elif auth.type == AuthType.APIKEY:
        if not getattr(auth, "api_key", None) or not getattr(
            auth, "api_key_header", None
        ):
            raise ValueError(
                "APIKEY authentication selected but no api key or api header value provided"
            )
        extra_headers[auth.api_key_header] = auth.api_key
        logger.debug(
            f'Using APIKEY authentication for MCP server: server="{server_url}"'
        )

    # Custom headers ride along with any auth type.
    if getattr(auth, "custom_headers", None):
        extra_headers.update(auth.custom_headers)

    return oauth_provider, extra_headers


def _build_client_context(
    dial_url: str,
    destination_url: str,
    extra_headers: Dict[str, str],
    oauth_provider: Optional[Any],
) -> Any:
    """Create the transport context for a server, SSE or streamable HTTP.

    For streamable HTTP the httpx client is created explicitly and stashed on
    the context, so ``close_mcp_session`` can close it even when the MCP
    library's own cleanup fails (a session-termination DELETE returning 404,
    for instance).
    """
    if not oauth_provider:
        logger.debug(
            f'Using standard connection (no auth) for MCP server: server="{destination_url}"'
        )

    httpx_client = None
    if "/sse" in destination_url:
        client_context = sse_client(
            dial_url,
            **({"headers": extra_headers} if extra_headers else {}),
            **({"auth": oauth_provider} if oauth_provider else {}),
        )
    else:
        httpx_client = create_mcp_http_client(
            headers=extra_headers if extra_headers else None,
            **({"auth": oauth_provider} if oauth_provider else {}),
        )
        client_context = streamable_http_client(dial_url, http_client=httpx_client)

    client_context._httpx_client = httpx_client
    return client_context


def _http_status_error(
    status_code: Optional[int], server_url: str, cause: Optional[Any] = None
) -> Optional[Exception]:
    """Map a captured HTTP status onto the error that explains it.

    Returns None when the status says nothing useful, leaving the caller to
    raise whichever generic connection error fits how the failure arrived.
    """
    detail = f" Original error: {cause}" if cause is not None else ""
    if status_code == 401:
        return MCPAuthenticationError(
            f"Authentication failed for MCP server at {server_url}. "
            f"This server requires OAuth or Bearer token authentication. "
            f"Use --bearer-token <token> or configure OAuth.{detail}"
        )
    if status_code == 403:
        return MCPAuthenticationError(
            f"Access denied to MCP server at {server_url}. "
            f"Check your authentication credentials.{detail}"
        )
    if status_code == 404:
        return MCPServerNotFoundError(
            f"MCP server endpoint not found at {server_url}. "
            f"Please verify the URL is correct.{detail}"
        )
    return None


def _looks_like_connection_failure(error: Exception) -> bool:
    """Whether an exception is really a failure to reach the host."""
    return (
        "ConnectError" in str(type(error))
        or "connection" in str(error).lower()
        or "nodename nor servname" in str(error)
    )


async def get_mcp_session(
    server_url: str,
    auth: Optional[Auth] = None,
    *,
    connector_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
) -> Tuple[Any, ClientSession]:
    """Create an MCP client session for the given server URL.

    Args:
        server_url (str): The URL of the MCP server.
        auth (Optional[Auth]): Explicit authentication configuration. If None, connects without auth.
        connector_id (Optional[str]): Hybrid connector ID for private MCP servers.
        tenant_id (Optional[str]): Tenant ID for hybrid proxy relay routing.

    Returns:
        tuple: A tuple containing (client_context, session)

    Raises:
        MCPAuthenticationError: If the server answered 401 or 403.
        MCPServerNotFoundError: If the server answered 404.
        MCPConnectionError: If the server could not be reached at all.
    """
    oauth_provider, extra_headers = _auth_headers(auth, server_url)

    destination_url = server_url
    dial_url, extra_headers = prepare_mcp_dial(
        destination_url,
        extra_headers,
        connector_id,
        tenant_id,
        streaming=True,
    )
    if is_hybrid_connector_id(connector_id):
        logger.debug(
            f'Using hybrid proxy relay for MCP server: destination="{destination_url}"'
        )

    client_context = _build_client_context(
        dial_url, destination_url, extra_headers, oauth_provider
    )
    session = None

    with _capture_http_status() as probe:
        try:
            logger.debug(f'Attempting to connect to MCP server: server="{server_url}"')
            # Suppress async generator warnings from MCP library cleanup bugs
            with warnings.catch_warnings():
                warnings.filterwarnings(
                    "ignore", category=RuntimeWarning, message=".*async.*generator.*"
                )
                read, write, *_ = await client_context.__aenter__()
                session = ClientSession(read, write)
                await session.__aenter__()
                logger.debug(f'Initializing MCP session: server="{server_url}"')
                # Stored on the session so instruction scans can read it later.
                session._init_result = await session.initialize()
            logger.debug(
                f'Successfully connected to MCP server: server="{server_url}"'
            )
            return client_context, session

        except (asyncio.CancelledError, GeneratorExit) as e:
            # These exceptions often wrap HTTP errors from the MCP library.
            await close_mcp_session(client_context, session)
            error = _http_status_error(probe.code, server_url)
            if error is None:
                error = MCPConnectionError(
                    f"Connection to MCP server at {server_url} was cancelled. "
                    f"This may indicate the server is not reachable, not responding, or requires authentication."
                )
            raise error from e

        except BaseExceptionGroup as eg:
            await close_mcp_session(client_context, session)
            first_error = eg.exceptions[0] if eg.exceptions else eg
            # The group may carry the status in its text even when httpx
            # logged nothing we could capture.
            detected = probe.code or check_http_error_in_logs(str(first_error))
            error = _http_status_error(detected, server_url, cause=first_error)
            if error is None:
                error = MCPConnectionError(
                    f"Error connecting to MCP server at {server_url}: {first_error}"
                )
            raise error from eg

        except Exception as e:
            await close_mcp_session(client_context, session)
            if _looks_like_connection_failure(e):
                raise MCPConnectionError(
                    f"Unable to connect to MCP server at {server_url}. "
                    f"Please verify the server is running and accessible. "
                    f"Original error: {e}"
                ) from e
            raise


async def get_stdio_session(
    server_config: StdioServer, timeout: int = 30, errlog: Any = None
) -> Tuple[Any, Any]:
    """Get a stdio session for the given server configuration.

    Args:
        server_config: The stdio server configuration
        timeout: Connection timeout in seconds
        errlog: Optional file-like object for stderr redirection (defaults to sys.stderr)

    Returns:
        Tuple of (client_context, session)
    """
    client_context = None
    session = None

    try:
        logger.debug(f"Creating stdio client for command: {server_config.command}")

        # Normalize and validate command/args to avoid FileNotFoundError ([Errno 2])
        # Expansion mode comes from StdioServer config; default is 'off'
        expand_mode = (server_config.expand_vars or "off").lower()
        logger.debug(
            f"expand_mode='{expand_mode}' for command: {server_config.command}"
        )
        env_for_expansion = build_env_for_expansion(server_config.env)
        windows_semantics = decide_windows_semantics(expand_mode)

        expanded_command, expanded_args = normalize_and_expand_command_args(
            server_config.command or "",
            server_config.args or [],
            env_for_expansion,
            expand_mode,
        )
        cmd_command, cmd_args = split_embedded_args(
            expanded_command, expanded_args, windows_semantics
        )
        resolved_exe = resolve_executable_path(cmd_command)
        if not resolved_exe or not os.path.exists(resolved_exe):
            # Provide a clear, actionable message and fail fast for this server only
            msg = (
                f"No such file or command: '{server_config.command}'. "
                f"Resolved path: '{resolved_exe or 'N/A'}'. "
                f"Tip: use absolute paths or ensure the binary is on PATH."
            )
            logger.warning(msg)
            raise MCPConnectionError(
                f"Unable to connect to stdio MCP server with command {server_config.command}. "
                f"Please verify the command is correct and executable."
            )

        # 5) Build parameters with normalized command/args
        # Merge parent process env with server-specific env (server config takes precedence)
        merged_env = {**os.environ, **(server_config.env or {})}
        server_params = StdioServerParameters(
            command=resolved_exe,
            args=cmd_args,
            env=merged_env,
        )

        # Create client context and session with proper error handling
        # Pass errlog for stderr redirection (helps avoid JSON corruption from startup messages)
        client_context = stdio_client(server_params, errlog=errlog if errlog else sys.stderr)

        # Use asyncio.wait_for for timeout instead of asyncio.timeout
        try:
            client_context_opened = await asyncio.wait_for(
                client_context.__aenter__(), timeout=timeout
            )
            read, write = client_context_opened

            session = ClientSession(read, write)
            await asyncio.wait_for(session.__aenter__(), timeout=10)
            await asyncio.wait_for(session.initialize(), timeout=10)

        except asyncio.TimeoutError:
            # Clean up on timeout
            await close_mcp_session(client_context, session)
            raise

        logger.debug(
            f"Successfully connected to stdio MCP server: {server_config.command}"
        )
        return client_context, session

    except asyncio.TimeoutError:
        logger.error(
            f"Timeout connecting to stdio server {server_config.command} after {timeout}s"
        )
        raise MCPConnectionError(
            f"Timeout connecting to stdio MCP server with command {server_config.command}. "
            f"Server took longer than {timeout} seconds to start."
        )
    except asyncio.CancelledError:
        logger.error(
            f"Connection cancelled for stdio server {server_config.command}"
        )
        # Clean up resources on cancellation
        await close_mcp_session(client_context, session)
        raise MCPConnectionError(
            f"Connection cancelled for stdio MCP server with command {server_config.command}. "
            f"This may indicate the server failed to start properly."
        )
    except Exception as e:
        logger.error(
            f"Error connecting to stdio server {server_config.command}: {e}"
        )
        # Clean up resources on error
        await close_mcp_session(client_context, session)
        raise MCPConnectionError(
            f"Unable to connect to stdio MCP server with command {server_config.command}. "
            f"Please verify the command is correct and executable. "
            f"Original error: {e}"
        ) from e
