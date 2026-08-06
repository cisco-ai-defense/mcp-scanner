# Hand-rolled Flask MCP demo (no SDK)

Minimal DIY MCP server over HTTP JSON-RPC — no `fastmcp`, `mcp.server`, or other MCP SDK imports. Mirrors common production patterns (Flask route + helper module with a `TOOLS` registry).

## Layout

```
server/
  app.py          # Flask POST /mcp → delegates to mcp_helper
  mcp_helper.py   # TOOLS registry + JSON-RPC dispatch
switch_dispatch.py  # Alternate DIY pattern (name switch, no registry) — coverage gap demo
scan_static.py    # Run NativeAnalyzer over the tree
```

## Run the server

```bash
cd evals/research-runs/hand-rolled-flask-mcp
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m server.app
```

Example `tools/list`:

```bash
curl -s http://127.0.0.1:8080/mcp \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":1}'
```

## Scan with mcp-scanner

From repo root:

```bash
# Static capability extraction (no LLM)
uv run python evals/research-runs/hand-rolled-flask-mcp/scan_static.py

# Full behavioral scan (requires MCP_SCANNER_LLM_API_KEY)
uv run mcp-scanner behavioral evals/research-runs/hand-rolled-flask-mcp/server -v
```

Expected static tools from `server/` (registry pattern): `add`, `search`, `status`.

`switch_dispatch.py` uses inline schema + `if tool_name == ...` dispatch — currently not extracted (known gap).
