---
description: Scan all known MCP configurations on this machine (Windsurf, Cursor, Claude, VS Code)
---

# Scan Known MCP Configurations

Scan all well-known MCP configuration locations on this machine for security vulnerabilities.

Run the following command:
```bash
mcp-scanner --scan-known-configs --analyzers yara --format detailed
```

This will scan MCP configurations from:
- Windsurf (~/.codeium/windsurf/mcp_config.json)
- Cursor
- Claude Desktop
- VS Code

After scanning, provide a summary of all findings grouped by configuration file and severity.
