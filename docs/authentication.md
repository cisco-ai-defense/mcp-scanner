# Authentication

## Explicit Authentication Control

The MCP Scanner SDK provides explicit authentication control through the `Auth` parameter. Authentication is **only used when explicitly provided** - no automatic fallback to config settings.

### Authentication Behavior

- **`auth=None` (default)**: Connects without authentication, regardless of config settings
- **`auth=Auth(...)` explicitly passed**: Uses the provided authentication configuration

```python
from mcpscanner import Config, Scanner, Auth, AuthType

# Create scanner with config (config OAuth settings are ignored unless explicitly used)
config = Config(
    api_key="your_cisco_api_key",
    llm_provider_api_key="your_llm_api_key"
)
scanner = Scanner(config)

# 1. Connect WITHOUT authentication (default behavior)
results = await scanner.scan_remote_server_tools(
    "http://localhost:8001/mcp",
    # No auth parameter = no authentication, even if config has OAuth
    api_scan=True,
    yara_scan=True,
    llm_scan=True
)

# 2. Connect WITH explicit OAuth authentication
auth = Auth.oauth(
    client_id="your_client_id",
    client_secret="your_client_secret",
    scopes=["user", "read:tools"]
)

results = await scanner.scan_remote_server_tools(
    "http://localhost:8001/mcp",
    auth=auth,  # Explicit auth parameter required
    api_scan=True,
    yara_scan=True,
    llm_scan=True
)

# 3. Explicitly disable authentication
no_auth = Auth(enabled=False)
results = await scanner.scan_remote_server_tools(
    "http://localhost:8001/mcp",
    auth=no_auth,  # Explicitly disabled
    api_scan=True,
    yara_scan=True,
    llm_scan=True
)
```

## OAuth Authentication

Full OAuth support for both SSE and streamable HTTP connections:

```python
from mcpscanner import Auth, AuthType, InMemoryTokenStorage

# Create OAuth authentication
auth = Auth.oauth(
    client_id="your_oauth_client_id",
    client_secret="your_oauth_client_secret",
    scopes=["user", "read:tools", "read:resources"],
    storage=InMemoryTokenStorage(),  # Optional: custom token storage
)

# Use with scanner
results = await scanner.scan_remote_server_tools(
    "http://localhost:8001/mcp",
    auth=auth
)

# Check authentication type
if auth and auth.type == AuthType.OAUTH:
    print("Using OAuth authentication")
```

## Bearer Authentication (non-OAuth)

Use a static bearer token for remote MCP servers that expect `Authorization: Bearer <token>`.

```python
from mcpscanner import Config, Scanner
from mcpscanner.core.auth import Auth

scanner = Scanner(Config())

# Remote server with bearer token
results = await scanner.scan_remote_server_tools(
    "https://your-mcp-server/sse",
    auth=Auth.bearer("YOUR_TOKEN")
)
```

### Bearer with Config-Based Scans (SDK)

Bearer is also supported when scanning well-known or specific MCP configs containing remote servers.

```python
from mcpscanner.core.models import AnalyzerEnum

# Scan well-known config files (Windsurf, Cursor, Claude, VS Code)
results_by_cfg = await scanner.scan_well_known_mcp_configs(
    analyzers=[AnalyzerEnum.YARA],
    auth=Auth.bearer("YOUR_TOKEN")
)

# Scan a specific MCP config file
results = await scanner.scan_mcp_config_file(
    config_path="/path/to/mcp_config.json",
    analyzers=[AnalyzerEnum.YARA],
    auth=Auth.bearer("YOUR_TOKEN")
)
```

### STDIO Scans (no auth required)

Stdio servers are launched locally and do not use bearer or OAuth.

```python
from mcpscanner.core.mcp_models import StdioServer

stdio = StdioServer(
    command="uvx",
    args=["--from", "mcp-server-fetch", "mcp-server-fetch"],
)

# Scan all tools on a stdio server
results = await scanner.scan_stdio_server_tools(stdio)

# Scan a specific tool
result = await scanner.scan_stdio_server_tool(stdio, tool_name="fetch")
```

## Conditional Authentication

Different authentication per server:

```python
servers = [
    {
        "url": "http://oauth-server:8001/mcp",
        "auth": Auth.oauth(client_id="oauth_client")
    },
    {
        "url": "http://public-server:8002/mcp",
        "auth": Auth(enabled=False)  # Explicitly no auth
    },
    {
        "url": "http://standard-server:8003/mcp",
        "auth": None  # No auth (default)
    }
]

for server in servers:
    results = await scanner.scan_remote_server_tools(
        server["url"],
        auth=server["auth"]  # Different auth per server
    )
```

## Custom OAuth Handlers

```python
async def custom_redirect_handler(auth_url: str) -> None:
    print(f"Please visit: {auth_url}")

async def custom_callback_handler() -> tuple[str, str | None]:
    callback_url = input("Paste callback URL: ")
    # Parse and return (code, state)
    return parse_callback_url(callback_url)

# Create Auth with custom handlers
auth = Auth.oauth(
    client_id="client_id",
    redirect_handler=custom_redirect_handler,
    callback_handler=custom_callback_handler
)
```
