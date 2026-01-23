---
description: Scan MCP server resources for security vulnerabilities
---

# Scan MCP Server Resources

Scan all resources on the MCP server at "$ARGUMENTS" for security vulnerabilities.

Run the following command:
```bash
mcp-scanner --analyzers llm --format detailed resources --server-url "$ARGUMENTS"
```

If the URL is not provided, ask the user for the MCP server URL.

Note: This scan requires the LLM analyzer. Ensure MCP_SCANNER_LLM_API_KEY is set.

After scanning, summarize any security concerns found in the server's resources.
