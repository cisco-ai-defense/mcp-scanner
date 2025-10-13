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

"""MCP Scanner exceptions.

This module defines custom exceptions for MCP Scanner operations.
All exceptions inherit from MCPScannerError for easy catching.

Example:
    >>> from mcpscanner import Scanner, Config
    >>> from mcpscanner.core.exceptions import MCPAuthenticationError
    >>>
    >>> config = Config()
    >>> scanner = Scanner(config)
    >>>
    >>> try:
    ...     results = await scanner.scan_remote_server_tools("https://server.com")
    ... except MCPAuthenticationError as e:
    ...     print(f"Auth required: {e}")
    ... except MCPConnectionError as e:
    ...     print(f"Connection failed: {e}")
"""


class MCPScannerError(Exception):
    """Base exception for all MCP Scanner errors."""
    pass


class MCPConnectionError(MCPScannerError):
    """Raised when unable to connect to an MCP server.

    This can indicate:
    - DNS resolution failure
    - Network connectivity issues
    - Server not reachable
    - Connection timeout
    """
    pass


class MCPAuthenticationError(MCPConnectionError):
    """Raised when authentication with an MCP server fails.

    This typically indicates:
    - HTTP 401 Unauthorized - Missing or invalid credentials
    - HTTP 403 Forbidden - Insufficient permissions

    The server requires authentication via OAuth or Bearer token.
    Use the --bearer-token flag or configure OAuth.
    """
    pass


class MCPServerNotFoundError(MCPConnectionError):
    """Raised when the MCP server endpoint is not found.

    This indicates:
    - HTTP 404 Not Found
    - Invalid URL or endpoint path
    """
    pass
