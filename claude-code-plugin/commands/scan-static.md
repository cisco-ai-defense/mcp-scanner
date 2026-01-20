---
description: Scan pre-generated JSON files offline without connecting to a live MCP server (CI/CD mode)
---

# Scan Static/Offline Files

Scan pre-generated MCP JSON files at "$ARGUMENTS" for security vulnerabilities. This mode is ideal for CI/CD pipelines, air-gapped environments, or reproducible security checks.

If the user provides a path, determine the file type and run the appropriate command:

**For tools JSON file:**
```bash
mcp-scanner --analyzers yara --format detailed static --tools "$ARGUMENTS"
```

**For prompts JSON file:**
```bash
mcp-scanner --analyzers llm --format detailed static --prompts "$ARGUMENTS"
```

**For resources JSON file:**
```bash
mcp-scanner --analyzers llm --format detailed static --resources "$ARGUMENTS"
```

**For scanning multiple files at once:**
```bash
mcp-scanner --analyzers yara,llm --format detailed static \
  --tools /path/to/tools.json \
  --prompts /path/to/prompts.json \
  --resources /path/to/resources.json
```

If no path is provided, ask the user for:
1. The path to the JSON file(s)
2. What type of MCP data it contains (tools, prompts, or resources)

## Expected JSON Format

```json
{
  "tools": [
    {
      "name": "tool_name",
      "description": "Tool description",
      "inputSchema": { "type": "object", "properties": {} }
    }
  ]
}
```

For CI/CD pipelines, recommend using `--analyzers yara --format summary` for quick scans that don't require API keys.
