---
description: Deep security scan using all analyzers (YARA, LLM, and Cisco AI Defense API)
---

# Deep Security Scan

Perform a comprehensive security scan of the MCP server at "$ARGUMENTS" using all available analyzers.

Run the following command:
```bash
mcp-scanner --analyzers yara,llm,api --format detailed remote --server-url "$ARGUMENTS"
```

If the URL is not provided, ask the user for the MCP server URL.

**Requirements:**
- MCP_SCANNER_LLM_API_KEY for LLM analysis
- MCP_SCANNER_API_KEY for Cisco AI Defense API analysis

If API keys are not configured, the scan will still run with available analyzers.

After scanning, provide a comprehensive report of all findings organized by severity level.
