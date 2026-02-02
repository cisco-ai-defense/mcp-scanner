---
description: Scan a specific MCP configuration file for security vulnerabilities
---

# Scan MCP Configuration File

Scan the MCP configuration file at path "$ARGUMENTS" for security vulnerabilities.

Run the following command:
```bash
mcp-scanner config --config-path "$ARGUMENTS" --analyzers yara --format detailed
```

If the path is not provided, ask the user for the path to the MCP configuration file.

After scanning, summarize the findings for each MCP server defined in the configuration.
