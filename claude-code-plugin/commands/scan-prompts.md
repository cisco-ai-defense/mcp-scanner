---
description: Scan MCP server prompts for prompt injection and other threats
---

# Scan MCP Server Prompts

Scan all prompts on the MCP server at "$ARGUMENTS" for security threats including prompt injection.

Run the following command:
```bash
mcp-scanner --analyzers llm --format detailed prompts --server-url "$ARGUMENTS"
```

If the URL is not provided, ask the user for the MCP server URL.

Note: This scan requires the LLM analyzer. Ensure MCP_SCANNER_LLM_API_KEY is set.

After scanning, summarize any prompt injection risks or other security concerns found.
