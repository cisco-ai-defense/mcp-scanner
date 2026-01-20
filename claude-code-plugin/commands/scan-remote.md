---
description: Scan a remote MCP server for security vulnerabilities
---

# Scan Remote MCP Server

Scan the remote MCP server at URL "$ARGUMENTS" for security vulnerabilities.

Run the following command:
```bash
mcp-scanner --analyzers yara --format detailed remote --server-url "$ARGUMENTS"
```

If the URL is not provided, ask the user for the MCP server URL to scan.

After scanning, summarize the findings and recommend next steps if any threats are detected.
