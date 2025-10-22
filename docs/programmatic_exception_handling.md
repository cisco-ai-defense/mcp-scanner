# MCP Scanner Programmatic Usage - Exception Handling

## Quick Start

The MCP Scanner Programmatic Usage raises specific exceptions for different error scenarios when used programmatically:

```python
from mcpscanner import Scanner, Config
from mcpscanner import (
    MCPAuthenticationError,  # 401/403 errors
    MCPServerNotFoundError,  # 404 errors
    MCPConnectionError,      # Network/DNS failures
)

scanner = Scanner(Config())

try:
    results = await scanner.scan_remote_server_tools("https://example.com/mcp")

except MCPAuthenticationError as e:
    print(f"Auth required: {e}")

except MCPServerNotFoundError as e:
    print(f"Not found: {e}")

except MCPConnectionError as e:
    print(f"Connection failed: {e}")
```

## Exception Types

### MCPAuthenticationError
- **When:** HTTP 401 or 403
- **Cause:** Missing credentials, invalid token, OAuth required
- **Fix:** Provide authentication via `--bearer-token` or OAuth config

### MCPServerNotFoundError
- **When:** HTTP 404
- **Cause:** Wrong URL or endpoint path
- **Fix:** Verify the URL is correct

### MCPConnectionError
- **When:** Network failures, DNS errors, timeouts
- **Cause:** Server down, DNS failure, network issues
- **Fix:** Check server status and network connectivity

## Simple Example

```python
from mcpscanner import Scanner, Config, MCPConnectionError

async def scan(url: str):
    scanner = Scanner(Config())
    try:
        return await scanner.scan_remote_server_tools(url)
    except MCPConnectionError:
        return []  # Return empty on error
```

## Catch All Errors

```python
from mcpscanner import MCPScannerError

try:
    results = await scanner.scan_remote_server_tools(url)
except MCPScannerError as e:
    # Catches all MCP scanner exceptions
    print(f"Error: {e}")
```

## With Authentication

```python
from mcpscanner import Auth, AuthType, MCPAuthenticationError

try:
    results = await scanner.scan_remote_server_tools(url)
except MCPAuthenticationError:
    # Retry with auth
    auth = Auth(type=AuthType.BEARER, token="your-token")
    results = await scanner.scan_remote_server_tools(url, auth=auth)
```

## Best Practice

Always catch specific exceptions first (most specific to most general):

```python
try:
    results = await scanner.scan_remote_server_tools(url)
except MCPAuthenticationError:
    # Handle auth errors
    pass
except MCPServerNotFoundError:
    # Handle 404 errors
    pass
except MCPConnectionError:
    # Handle other connection errors
    pass
```

See `examples/programmatic_exception_handling.py` for a complete working example.
