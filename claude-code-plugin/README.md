# MCP Scanner - Claude Code Plugin

A Claude Code plugin for scanning MCP servers and tools for security vulnerabilities using YARA rules, LLM analysis, and Cisco AI Defense API.

## Features

- **Quick YARA Scans**: Fast pattern-based security detection without API keys
- **LLM Analysis**: Deep semantic analysis for prompt injection and tool poisoning
- **Behavioral Analysis**: Detect mismatches between documentation and implementation
- **Multi-target Scanning**: Scan remote servers, local configs, prompts, and resources

## Installation

### Prerequisites

1. Install MCP Scanner:
   ```bash
   pip install cisco-ai-mcp-scanner
   ```

2. (Optional) Set environment variables for advanced scanning:
   ```bash
   export MCP_SCANNER_LLM_API_KEY="your_llm_api_key"
   export MCP_SCANNER_API_KEY="your_cisco_api_key"
   ```

### Install Plugin

Load the plugin in Claude Code:

```bash
claude --plugin-dir /path/to/claude-code-plugin
```

Or install from a marketplace if published.

## Commands

All commands are namespaced under `mcp-scanner:`. Use `/help` in Claude Code to see available commands.

| Command | Description |
|---------|-------------|
| `/mcp-scanner:quick-scan <url>` | Quick YARA-only scan (no API keys needed) |
| `/mcp-scanner:deep-scan <url>` | Full scan with all analyzers |
| `/mcp-scanner:scan-remote <url>` | Scan a remote MCP server |
| `/mcp-scanner:scan-known-configs` | Scan all known MCP configs on this machine |
| `/mcp-scanner:scan-config <path>` | Scan a specific MCP config file |
| `/mcp-scanner:scan-prompts <url>` | Scan server prompts for injection risks |
| `/mcp-scanner:scan-resources <url>` | Scan server resources |
| `/mcp-scanner:scan-behavioral <path>` | Analyze MCP server source code |
| `/mcp-scanner:scan-static <path>` | Scan pre-generated JSON files (CI/CD mode) |

## Skills

The plugin includes an `mcp-security-scan` skill that Claude will automatically use when you ask about MCP security scanning.

**Example prompts:**
- "Scan my MCP configurations for security issues"
- "Check this MCP server for vulnerabilities: https://example.com/mcp"
- "Analyze the security of this MCP server code"

## Analyzers

| Analyzer | Description | Requirements |
|----------|-------------|--------------|
| `yara` | Pattern-based threat detection | None |
| `llm` | LLM-powered semantic analysis | `MCP_SCANNER_LLM_API_KEY` |
| `api` | Cisco AI Defense API | `MCP_SCANNER_API_KEY` |

## Output Formats

Use `--format` with any scan command:
- `summary` - Concise overview
- `detailed` - Full findings breakdown
- `table` - Tabular format
- `by_severity` - Grouped by severity
- `raw` - Raw JSON output

## Examples

### Scan known configurations
```
/mcp-scanner:scan-known-configs
```

### Quick scan a remote server
```
/mcp-scanner:quick-scan https://mcp.example.com/mcp
```

### Deep security analysis
```
/mcp-scanner:deep-scan https://mcp.example.com/mcp
```

### Analyze MCP server source code
```
/mcp-scanner:scan-behavioral ./my-mcp-server/
```

### Static/offline scanning (CI/CD mode)
```
/mcp-scanner:scan-static ./output/tools.json
```

## License

Apache 2.0 - See [LICENSE](../LICENSE) for details.

## Links

- [MCP Scanner Repository](https://github.com/cisco-ai-defense/mcp-scanner)
- [Documentation](https://github.com/cisco-ai-defense/mcp-scanner/tree/main/docs)
- [Cisco AI Defense](https://www.cisco.com/site/us/en/products/security/ai-defense/index.html)
