# MCP Scanner 

A Python tool for scanning MCP (Model Context Protocol) servers and tools for potential security vulnerabilities. The MCP Scanner combines Cisco AI Defense inspect API, YARA rules and LLM-as-a-judge to detect malicious MCP tools.

## Overview

The MCP Scanner provides a comprehensive solution for scanning MCP servers and tools for security vulnerabilities. It leverages three powerful scanning engines (Yara, LLM-as-judge, Cisco AI Defense) that can be used together or independently.

The SDK is designed to be easy to use while providing powerful scanning capabilities, flexible authentication options, and customization.

![MCP Scanner](https://github.com/cisco-ai-defense/mcp-scanner/raw/main/images/mcp_scanner.gif?raw=true)


## Features

- **Multiple Modes:** Run scanner as a stand-alone CLI tool or REST API server
- **Multi-Engine Security Analysis**: Use all three scanning engines together or independently based on your needs.
- **Explicit Authentication Control**: Fine-grained control over authentication with explicit Auth parameters.
- **OAuth Support**: Full OAuth authentication support for both SSE and streamable HTTP connections.
- **Custom Endpoints**: Configure the API endpoint to support any Cisco AI Defense environments.
- **MCP Server Integration**: Connect directly to MCP servers to scan tools with flexible authentication.
- **Customizable YARA Rules**: Add your own YARA rules to detect specific patterns.
- **Comprehensive Vulnerability Reporting**: Detailed reports on detected vulnerabilities.

## Installation

### Prerequisites

- Python 3.11+
- uv (Python package manager)
- A valid Cisco AI Defense API Key (optional)
- LLM Provider API Key (optional)

### Installing from Source

```bash
git clone https://github.com/cisco-ai-defense/mcp-scanner
cd mcp-scanner
# Install with uv (recommended)

uv venv -p <Python version less than or equal to 3.13> /path/to/your/choice/of/venv/directory

source /path/to/your/choice/of/venv/directory/bin/activate

uv pip install .
# Or install in development mode
uv pip install -e .



```

## Quick Start

### Environment Setup

#### Core API Configuration

```bash
Cisco AI Defense API (only required for API analyzer)
export MCP_SCANNER_API_KEY="your_cisco_api_key"
export MCP_SCANNER_ENDPOINT="https://us.api.inspect.aidefense.security.cisco.com/api/v1"
# For other endpoints please visit https://developer.cisco.com/docs/ai-defense/getting-started/#base-url
```

#### LLM Configuration (for LLM analyzer)

**Tested LLMs:** OpenAI GPT-4o and GPT-4.1

```bash
# LLM Provider API Key (required for LLM analyzer)
export MCP_SCANNER_LLM_API_KEY="your_llm_api_key"  # OpenAI

# LLM Model Configuration (optional - defaults provided)
export MCP_SCANNER_LLM_MODEL="gpt-4o"  # Any LiteLLM-supported model
export MCP_SCANNER_LLM_BASE_URL="https://api.openai.com/v1"  # Custom LLM endpoint
export MCP_SCANNER_LLM_API_VERSION="2024-02-01"  # API version (if required)

# For Azure OpenAI (example)
export MCP_SCANNER_LLM_BASE_URL="https://your-resource.openai.azure.com/"
export MCP_SCANNER_LLM_API_VERSION="2024-02-01"
export MCP_SCANNER_LLM_MODEL="azure/gpt-4"
```

### Quick Start

The fastest way to get started is using the `mcp-scanner` CLI command. Global flags (like `--analyzers`, `--format`, etc.) must be placed before a subcommand.

#### CLI Usage

```bash
# Scan well-known client configs on this machine
mcp-scanner --scan-known-configs --analyzers yara --format summary

# Stdio server (example using uvx mcp-server-fetch)
mcp-scanner --stdio-command uvx --stdio-arg=--from --stdio-arg=mcp-server-fetch --stdio-arg=mcp-server-fetch --analyzers yara --format summary

# Remote server (deepwiki example)
mcp-scanner --server-url https://mcp.deepwki.com/mcp --analyzers yara --format summary

# MCP Scanner as REST API
mcp-scanner-api --host 0.0.0.0 --port 8080

```

#### SDK Usage

```python
import asyncio
from mcpscanner import Config, Scanner

async def main():
    # Create configuration with your API keys
    config = Config(
        api_key="your_cisco_api_key",
        llm_provider_api_key="your_llm_api_key"
    )
    
    # Create scanner
    scanner = Scanner(config)
    
    # Scan all tools on a remote server
    results = await scanner.scan_remote_server_tools(
        "https://mcp.deepwki.com/mcp",
        api_scan=True,    # Cisco AI Defense
        yara_scan=True,   # YARA rules
        llm_scan=True     # LLM analysis
    )
    
    # Print results
    for result in results:
        print(f"Tool: {result.tool_name}, Safe: {result.is_safe}")

# Run the scanner
asyncio.run(main())
```

#### Subcommands Overview

- remote: scan a remote MCP server (SSE or streamable HTTP). Supports `--server-url`, optional `--bearer-token`.
- stdio: launch and scan a stdio MCP server. Requires `--stdio-command`; accepts `--stdio-args`, `--stdio-env`, optional `--stdio-tool`.
- config: scan servers from a specific MCP config file. Requires `--config-path`; optional `--bearer-token`.
- known-configs: scan servers from well-known client config locations on this machine; optional `--bearer-token`.

Note: Top-level flags (e.g., `--server-url`, `--stdio-*`, `--config-path`, `--scan-known-configs`) remain supported when no subcommand is used, but subcommands are recommended.

#### Additional Examples

#### Scan well-known MCP config paths (Windsurf, Cursor, Claude, VS Code)

```bash
# YARA-only scan of all servers defined in well-known config locations
mcp-scanner --scan-known-configs --analyzers yara --format summary

# Detailed output
mcp-scanner --scan-known-configs --analyzers yara --detailed
```

#### Scan a specific MCP config file

```bash
# Expand ~ yourself if needed by your shell
mcp-scanner --config-path "$HOME/.codeium/windsurf/mcp_config.json" \
 --analyzers yara --format by_tool
```

#### Scan a stdio MCP server

```bash
# Use repeated --stdio-arg for reliable argument passing
mcp-scanner --analyzers yara --format summary \
  stdio --stdio-command uvx \
  --stdio-arg=--from --stdio-arg=mcp-server-fetch --stdio-arg=mcp-server-fetch

# Or list-form (ensure it doesn't conflict with later flags)
mcp-scanner --analyzers yara --detailed \
  stdio --stdio-command uvx \
  --stdio-args --from mcp-server-fetch mcp-server-fetch

# Scan only a specific tool on the stdio server
mcp-scanner --analyzers yara --format summary \
  stdio --stdio-command uvx \
  --stdio-arg=--from --stdio-arg=mcp-server-fetch --stdio-arg=mcp-server-fetch \
  --stdio-tool fetch
```

#### Use a Bearer token with remote servers (non-OAuth)

```bash
# Direct remote server with Bearer token
mcp-scanner --analyzers yara --format summary \
  remote --server-url https://your-mcp-server/sse --bearer-token "$TOKEN"

# Apply Bearer token to all remote servers discovered from configs
mcp-scanner --analyzers yara --detailed known-configs --bearer-token "$TOKEN"
mcp-scanner --analyzers yara --format by_tool \
  config --config-path "$HOME/.codeium/windsurf/mcp_config.json" --bearer-token "$TOKEN"
```

### API Server Usage

The API server provides a REST interface to the MCP scanner functionality, allowing you to integrate security scanning into web applications, CI/CD pipelines, or other services. It exposes the same scanning capabilities as the CLI tool but through HTTP endpoints.

```bash
# Start the API server (loads configuration from .env file)
mcp-scanner-api --port 8000

# Or with custom host and port
mcp-scanner-api --host 0.0.0.0 --port 8080

# Enable development mode with auto-reload
mcp-scanner-api --reload
```

Once running, the API server provides endpoints for:
- **`/scan-tool`** - Scan a specific tool on an MCP server
- **`/scan-all-tools`** - Scan all tools on an MCP server
- **`/health`** - Health check endpoint

Documentation is available in [docs/api-reference.md](docs/api-reference.md) or as interactive documentation at `http://localhost:8000/docs` when the server is running.

## Output Formats

The scanner supports multiple output formats:

- **`summary`**: Concise overview with key findings
- **`detailed`**: Comprehensive analysis with full findings breakdown
- **`table`**: Clean tabular format  
- **`by_severity`**: Results grouped by severity level
- **`raw`**: Raw JSON output

### Example Output

#### Detailed Format

```bash
mcp-scanner --server-url http://127.0.0.1:8001/sse --format detailed
```

```
=== MCP Scanner Detailed Results ===

Scan Target: http://127.0.0.1:8001/sse

Tool: execute_system_command
Status: completed
Safe: No
Analyzer Results:
  • api_analyzer:
    - Severity: HIGH
    - Threat Summary: Detected 1 threat: security violation
    - Threat Names: SECURITY VIOLATION
    - Total Findings: 1
  • yara_analyzer:
    - Severity: HIGH
    - Threat Summary: Detected 2 threats: system access, command injection
    - Threat Names: SECURITY VIOLATION, SUSPICIOUS CODE EXECUTION
    - Total Findings: 2
  • llm_analyzer:
    - Severity: HIGH
    - Threat Summary: Detected 2 threats: prompt injection, tool poisoning
    - Threat Names: PROMPT INJECTION, SUSPICIOUS CODE EXECUTION
    - Total Findings: 2
```

#### Table Format

```bash
mcp-scanner --server-url http://127.0.0.1:8002/sse --format table
```

```
=== MCP Scanner Results Table ===

Scan Target: http://127.0.0.1:8002/sse

Scan Target                   Tool Name     Status     API      YARA     LLM      Severity   
-----------------------------------------------------------------------------------------
http://127.0.0.1:8002/sse     exec_secrets  UNSAFE     HIGH     HIGH     HIGH     HIGH      
http://127.0.0.1:8002/sse     safe_command  SAFE       SAFE     SAFE     SAFE     SAFE  
```

## Documentation

For detailed documentation, see the [docs/](docs/) directory:

- **[Architecture](docs/architecture.md)** - System architecture and components
- **[Authentication](docs/authentication.md)** - OAuth and security configuration
- **[Programmatic Usage](docs/programmatic-usage.md)** - Programmatic usage examples and advanced usage
- **[API Reference](docs/api-reference.md)** - Complete REST API documentation
- **[Output Formats](docs/output-formats.md)** - Detailed output format options


## Contact Cisco for obtaining an AI Defense subscription

https://www.cisco.com/site/us/en/products/security/ai-defense/index.html

## License

Distributed under the `Apache 2.0` License. See [LICENSE](LICENSE) for more information.

Project Link: [https://github.com/cisco-ai-defense/mcp-scanner](https://github.com/cisco-ai-defense/mcp-scanner)
