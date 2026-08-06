# Python MCP framework detection fixtures

Runnable-ish demo servers for every Python MCP integration pattern detected by
`NativeAnalyzer`. Used by `scan_all.py` and
`tests/static_analysis/test_python_mcp_framework_fixtures.py`.

## Frameworks covered

| Directory | Pattern | Expected tools |
|-----------|---------|----------------|
| `01_fastmcp_decorator` | PrefectHQ `fastmcp` `@mcp.tool` | `add` |
| `02_official_sdk_fastmcp` | `mcp.server.fastmcp.FastMCP` | `ping` |
| `03_programmatic_add_tool` | `mcp.add_tool(fn)` | `multiply` |
| `04_mcpserver_v2` | `mcp.server.mcpserver.MCPServer` `@app.tool` | `greet` |
| `05_fastapi_mcp_app` | Tadata `FastApiMCP` + `operation_id` routes | `list_items`, `create_item` |
| `06_fastapi_mcp_router` | `FastApiMCP(APIRouter)` | `health_check` |
| `07_vanilla_fastapi_mcp_mount` | Official SDK `MCPServer` + `streamable_http_app` | `add_note` |
| `08_fastmcp_http_app_mount` | FastMCP `http_app` mounted on FastAPI | `greet` |
| `09_flask_mcp_server` | `flask_mcp_server` `@Mcp.tool` | `sum_numbers` |
| `10_pagerduty_registration` | `add_read_only_tool(mcp, fn)` wrapper | `list_incidents` |
| `11_pagerduty_tool_module` | Split `tools/` package (behavioral expansion) | `list_incidents`, `list_alerts` |
| `12_hand_rolled_flask` | DIY Flask + `TOOLS` registry | `add`, `search` |
| `13_hand_rolled_fastapi` | DIY FastAPI + `TOOLS` registry | `add`, `list_items` |
| `14_hand_rolled_fastapi_router` | DIY APIRouter + `tool_handlers` | `echo` |
| `15_hand_rolled_register` | DIY `register_tool(name, fn)` | `multiply` |
| `negative/flask_rest_only` | Plain Flask REST (no MCP) | *(none)* |
| `negative/fastapi_rest_only` | Plain FastAPI REST (no MCP) | *(none)* |
| `negative/lambda_dispatch` | DIY lambda dispatch table | *(none — gap)* |

## Scan

From repo root:

```bash
uv run python evals/research-runs/python-mcp-frameworks/scan_all.py
uv run pytest tests/static_analysis/test_python_mcp_framework_fixtures.py -v
```
