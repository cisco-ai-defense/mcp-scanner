---
description: Quick YARA-only scan of an MCP server (no API keys required)
---

# Quick Security Scan

Perform a quick YARA-based security scan of the MCP server at "$ARGUMENTS".

This scan uses only YARA rules and does not require any API keys.

Run the following command:
```bash
mcp-scanner --analyzers yara --format summary remote --server-url "$ARGUMENTS"
```

If the URL is not provided, ask the user for the MCP server URL.

After scanning, provide a brief summary and suggest running a deeper scan with LLM analysis if any issues are found.
