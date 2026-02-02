---
name: mcp-security-scan
description: Scans MCP servers, tools, prompts, and resources for security vulnerabilities using YARA rules, LLM analysis, and Cisco AI Defense API. Use this skill when the user wants to check MCP servers for security issues, detect prompt injection, tool poisoning, or analyze MCP configurations for threats.
---

# MCP Security Scanning

When the user asks to scan MCP servers or check for security issues in MCP configurations, use the `uv run mcp-scanner` CLI tool. This tool detects prompt injection, tool poisoning, command injection, data exfiltration, and other MCP-specific threats.

**Important:** Always run mcp-scanner using `uv run mcp-scanner` to ensure proper dependency management.

## Threat Types Detected

- **Prompt Injection**: Malicious instructions embedded in tool descriptions or prompts
- **Tool Poisoning**: Tools that claim to do one thing but actually perform malicious actions
- **Command Injection**: Tools that execute arbitrary system commands
- **Data Exfiltration**: Tools that leak sensitive data to external endpoints
- **Privilege Escalation**: Tools that request excessive permissions
- **Cross-Origin Attacks**: Tools that access unauthorized resources
- **Behavioral Mismatches**: Discrepancies between documented and actual tool behavior

## Analyzers

| Analyzer | Description | Requirements | Best For |
|----------|-------------|--------------|----------|
| `yara` | Fast pattern-based detection using YARA rules | None | Quick scans, CI/CD pipelines |
| `llm` | LLM-powered semantic analysis | `MCP_SCANNER_LLM_API_KEY` | Deep analysis, prompt injection detection |
| `api` | Cisco AI Defense API | `MCP_SCANNER_API_KEY` | Enterprise-grade threat detection |

**Combine analyzers**: `--analyzers yara,llm,api` for comprehensive scanning.

## Scanning Modes

### 1. Remote MCP Server
Scan tools on a remote SSE or streamable HTTP MCP server:
```bash
# Basic scan
uv run mcp-scanner --analyzers yara remote --server-url https://mcp.example.com/mcp

# With authentication
uv run mcp-scanner --analyzers yara remote --server-url https://mcp.example.com/mcp --bearer-token "$TOKEN"

# With custom headers (e.g., MCP Gateway dual-token auth)
uv run mcp-scanner --analyzers yara remote --server-url https://gateway.example.com/mcp \
  --header "Authorization: Bearer ingress-token" \
  --header "X-Egress-Auth: Bearer egress-token"
```

### 2. Known Config Locations
Scan well-known MCP config paths (Windsurf, Cursor, Claude Desktop, VS Code):
```bash
# Quick summary scan
uv run mcp-scanner --scan-known-configs --analyzers yara --format summary

# Detailed scan
uv run mcp-scanner --scan-known-configs --analyzers yara --format detailed

# With authentication for remote servers in configs
uv run mcp-scanner known-configs --bearer-token "$TOKEN" --analyzers yara
```

**Config locations scanned:**
- `~/.codeium/windsurf/mcp_config.json` (Windsurf)
- `~/.cursor/mcp.json` (Cursor)
- `~/Library/Application Support/Claude/claude_desktop_config.json` (Claude Desktop on macOS)
- VS Code MCP settings

### 3. Specific Config File
Scan a specific MCP configuration file:
```bash
uv run mcp-scanner config --config-path /path/to/mcp_config.json --analyzers yara --format detailed
```

### 4. Stdio MCP Server
Launch and scan a stdio-based MCP server:
```bash
# Using uvx
uv run mcp-scanner stdio --stdio-command uvx \
  --stdio-arg=--from --stdio-arg=mcp-server-fetch --stdio-arg=mcp-server-fetch \
  --analyzers yara --format summary

# Scan specific tool only
uv run mcp-scanner stdio --stdio-command uvx \
  --stdio-arg=--from --stdio-arg=mcp-server-fetch --stdio-arg=mcp-server-fetch \
  --stdio-tool fetch --analyzers yara

# With environment variables
uv run mcp-scanner stdio --stdio-command python --stdio-arg=server.py \
  --stdio-env API_KEY=secret --analyzers yara
```

### 5. Prompts
Scan MCP server prompts for prompt injection and manipulation:
```bash
# Scan all prompts
uv run mcp-scanner --analyzers llm prompts --server-url http://127.0.0.1:8000/mcp

# Scan specific prompt
uv run mcp-scanner --analyzers llm prompts --server-url http://127.0.0.1:8000/mcp --prompt-name "greet_user"

# Table format output
uv run mcp-scanner --analyzers llm --format table prompts --server-url http://127.0.0.1:8000/mcp
```

### 6. Resources
Scan MCP server resources for malicious content:
```bash
# Scan all resources
uv run mcp-scanner --analyzers llm resources --server-url http://127.0.0.1:8000/mcp

# Scan specific resource
uv run mcp-scanner --analyzers llm resources --server-url http://127.0.0.1:8000/mcp \
  --resource-uri "file://test/document.txt"

# Filter by MIME types
uv run mcp-scanner --analyzers llm resources --server-url http://127.0.0.1:8000/mcp \
  --mime-types "text/plain,text/html,application/json"
```

### 7. Server Instructions
Scan server instructions from InitializeResult for prompt injection and misleading guidance:
```bash
uv run mcp-scanner instructions --server-url http://127.0.0.1:8000/mcp

# With LLM for semantic analysis
uv run mcp-scanner --analyzers llm instructions --server-url http://127.0.0.1:8000/mcp
```

### 8. Behavioral Code Analysis
Analyze MCP server source code to detect mismatches between documentation and implementation:
```bash
# Scan a single file
uv run mcp-scanner behavioral /path/to/mcp_server.py

# Scan a directory
uv run mcp-scanner behavioral /path/to/mcp_servers/

# With specific output format
uv run mcp-scanner behavioral /path/to/mcp_server.py --format by_severity

# Save results to file
uv run mcp-scanner behavioral /path/to/mcp_server.py --output results.json --format raw
```

**Detects:**
- Functions that claim to read but actually write
- Hidden network calls not mentioned in documentation
- Credential harvesting disguised as helper functions
- Data exfiltration in seemingly benign operations

### 9. Static/Offline Scanning (CI/CD Mode)
Scan pre-generated JSON files without connecting to a live server:
```bash
# Scan tools JSON (YARA-only, no API keys needed)
uv run mcp-scanner --analyzers yara --format summary static --tools /path/to/tools.json

# Scan prompts JSON
uv run mcp-scanner --analyzers llm static --prompts /path/to/prompts.json

# Scan resources JSON
uv run mcp-scanner --analyzers llm static --resources /path/to/resources.json

# Scan all types at once
uv run mcp-scanner --analyzers yara,llm,api --format detailed static \
  --tools /path/to/tools.json \
  --prompts /path/to/prompts.json \
  --resources /path/to/resources.json
```

**Expected JSON format:**
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

## Output Formats

| Format | Description | Use Case |
|--------|-------------|----------|
| `summary` | Concise overview with key findings | Quick checks |
| `detailed` | Comprehensive analysis with full breakdown | Investigation |
| `table` | Clean tabular format | Reports |
| `by_severity` | Results grouped by severity level | Prioritization |
| `raw` | Raw JSON output | Automation/CI |

## Environment Variables

### Core Configuration
```bash
# Cisco AI Defense API (for api analyzer)
export MCP_SCANNER_API_KEY="your_cisco_api_key"
export MCP_SCANNER_ENDPOINT="https://us.api.inspect.aidefense.security.cisco.com/api/v1"
```

### LLM Configuration
```bash
# OpenAI
export MCP_SCANNER_LLM_API_KEY="your_openai_api_key"
export MCP_SCANNER_LLM_MODEL="gpt-4o"

# Azure OpenAI
export MCP_SCANNER_LLM_BASE_URL="https://your-resource.openai.azure.com/"
export MCP_SCANNER_LLM_API_VERSION="2024-02-01"
export MCP_SCANNER_LLM_MODEL="azure/gpt-4"

# AWS Bedrock Claude
export AWS_PROFILE="your-profile"
export AWS_REGION="us-east-1"
export MCP_SCANNER_LLM_MODEL="bedrock/anthropic.claude-sonnet-4-5-20250929-v2:0"

# Local LLM (Ollama, vLLM, LocalAI)
export MCP_SCANNER_LLM_API_KEY="test"  # Required but can be any value
export MCP_SCANNER_LLM_ENDPOINT="http://localhost:11434"

# Extended thinking models (longer timeout)
export MCP_SCANNER_LLM_TIMEOUT=300
```

## Severity Levels

- **HIGH**: Critical security issues requiring immediate attention
- **MEDIUM**: Potential security concerns that should be reviewed
- **LOW**: Minor issues or informational findings
- **SAFE**: No security issues detected

## Best Practices

1. **Start with YARA**: Use `--analyzers yara` for quick initial scans (no API keys needed)
2. **Add LLM for depth**: Include `llm` analyzer for semantic analysis of suspicious tools
3. **Use detailed format**: Use `--format detailed` when investigating findings
4. **CI/CD integration**: Use static scanning with `--format raw` for pipeline integration
5. **Scan before install**: Always scan new MCP servers before adding to your configuration
6. **Regular rescans**: Periodically rescan existing configurations for new threats

## Example Workflow

```bash
# 1. Quick scan of all local configs
uv run mcp-scanner --scan-known-configs --analyzers yara --format summary

# 2. If issues found, run detailed scan
uv run mcp-scanner --scan-known-configs --analyzers yara,llm --format detailed

# 3. For new server, scan before installing
uv run mcp-scanner --analyzers yara,llm remote --server-url https://new-mcp-server.com/mcp

# 4. For MCP server code you're reviewing
uv run mcp-scanner behavioral ./mcp-server-source/ --format by_severity
```
