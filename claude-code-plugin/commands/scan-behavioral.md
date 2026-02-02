---
description: Perform behavioral analysis on MCP server source code to detect mismatches between documentation and implementation
---

# Behavioral Code Analysis

Perform behavioral analysis on the MCP server source code at "$ARGUMENTS" to detect:
- Mismatches between docstring claims and actual implementation
- Hidden malicious behaviors
- Security vulnerabilities in the code

Run the following command:
```bash
mcp-scanner behavioral "$ARGUMENTS" --format detailed
```

If the path is not provided, ask the user for the path to the MCP server source code file or directory.

This analysis requires the LLM analyzer, so ensure MCP_SCANNER_LLM_API_KEY is set.

After scanning, explain any behavioral mismatches found and their potential security implications.
