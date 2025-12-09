# examples/AGENTS.md

This file provides detailed context for AI coding agents working on **usage examples** in the `examples/` directory.

**📁 Parent Guide:** [`../AGENTS.md`](../AGENTS.md) - Global project overview and rules

---

## Overview

The `examples/` directory contains 40+ example scripts demonstrating how to use the MCP Scanner programmatically and via CLI. These examples cover different scan modes, custom analyzer configurations, exception handling, output processing, and integration patterns.

## Directory Structure

```
examples/
├── scan_instructions_example.py           # Scanning server instructions
├── programmatic_exception_handling.py     # Error handling patterns
├── scan_remote_server.py                  # Remote server scanning
├── scan_local_code.py                     # Local code scanning
├── scan_stdio_server.py                   # Stdio server scanning
├── scan_prompts.py                        # Prompt scanning
├── scan_resources.py                      # Resource scanning
├── custom_analyzer_config.py              # Custom analyzer setup
├── output_processing.py                   # Processing scan results
├── batch_scanning.py                      # Batch scanning multiple servers
├── example-bearer-server/                 # Example server with bearer auth
├── example-malicious-servers/             # Example malicious servers for testing
├── example-oauth-server-clients/          # Example OAuth integration
├── prompts/                               # Example prompt files
├── resources/                             # Example resource files
└── ... (30+ more examples)
```

## Example Categories

### 1. Basic Scanning Examples

#### Scan Remote Server
```python
# examples/scan_remote_server.py
import asyncio
from mcpscanner.core.scanner import Scanner
from mcpscanner.config.config import Config

async def main():
    config = Config(
        llm_api_key="your-api-key",
        llm_model="gpt-4o"
    )
    
    scanner = Scanner(config)
    results = await scanner.scan_remote_server(
        server_url="https://example.com/mcp",
        analyzers=["behavioral", "llm", "yara"]
    )
    
    print(f"Found {len(results)} findings")
    for result in results:
        print(f"- {result.severity}: {result.summary}")

if __name__ == "__main__":
    asyncio.run(main())
```

#### Scan Local Code
```python
# examples/scan_local_code.py
import asyncio
from mcpscanner.core.scanner import Scanner
from mcpscanner.config.config import Config

async def main():
    config = Config(
        llm_api_key="your-api-key",
        llm_model="gpt-4o"
    )
    
    scanner = Scanner(config)
    results = await scanner.scan_local_code(
        path="/path/to/mcp-server",
        analyzers=["behavioral"]
    )
    
    # Process results
    for tool_result in results:
        print(f"Tool: {tool_result.tool_name}")
        for finding in tool_result.findings:
            print(f"  - {finding.severity}: {finding.summary}")

if __name__ == "__main__":
    asyncio.run(main())
```

### 2. Advanced Scanning Examples

#### Scan Stdio Server
```python
# examples/scan_stdio_server.py
import asyncio
from mcpscanner.core.scanner import Scanner
from mcpscanner.config.config import Config

async def main():
    config = Config(
        llm_api_key="your-api-key",
        llm_model="gpt-4o"
    )
    
    scanner = Scanner(config)
    results = await scanner.scan_stdio_server(
        command="npx",
        args=["-y", "@modelcontextprotocol/server-filesystem"],
        analyzers=["llm", "yara"]
    )
    
    print(f"Scanned {len(results)} tools")

if __name__ == "__main__":
    asyncio.run(main())
```

#### Scan Prompts and Resources
```python
# examples/scan_prompts.py
import asyncio
from mcpscanner.core.scanner import Scanner
from mcpscanner.config.config import Config

async def main():
    config = Config(
        llm_api_key="your-api-key",
        llm_model="gpt-4o"
    )
    
    scanner = Scanner(config)
    
    # Scan prompts
    prompt_results = await scanner.scan_prompts(
        server_url="https://example.com/mcp",
        analyzers=["llm", "api"]
    )
    
    # Scan resources
    resource_results = await scanner.scan_resources(
        server_url="https://example.com/mcp",
        analyzers=["llm", "api"]
    )
    
    print(f"Prompt findings: {len(prompt_results)}")
    print(f"Resource findings: {len(resource_results)}")

if __name__ == "__main__":
    asyncio.run(main())
```

### 3. Exception Handling Examples

#### Comprehensive Error Handling
```python
# examples/programmatic_exception_handling.py
import asyncio
from mcpscanner.core.scanner import Scanner
from mcpscanner.core.exceptions import (
    ScannerError,
    ConfigurationError,
    AnalyzerError,
    MCPConnectionError
)
from mcpscanner.config.config import Config

async def scan_with_error_handling():
    try:
        config = Config(
            llm_api_key="your-api-key",
            llm_model="gpt-4o"
        )
        
        scanner = Scanner(config)
        results = await scanner.scan_remote_server(
            server_url="https://example.com/mcp",
            analyzers=["behavioral", "llm"]
        )
        
        return results
        
    except ConfigurationError as e:
        print(f"Configuration error: {e}")
        print("Please check your environment variables")
        return None
        
    except MCPConnectionError as e:
        print(f"Connection error: {e}")
        print("Could not connect to MCP server")
        return None
        
    except AnalyzerError as e:
        print(f"Analyzer error: {e}")
        print("One or more analyzers failed")
        return None
        
    except ScannerError as e:
        print(f"Scanner error: {e}")
        return None
        
    except Exception as e:
        print(f"Unexpected error: {e}")
        return None

async def main():
    results = await scan_with_error_handling()
    
    if results:
        print(f"Scan completed successfully with {len(results)} findings")
    else:
        print("Scan failed")

if __name__ == "__main__":
    asyncio.run(main())
```

### 4. Custom Configuration Examples

#### Custom Analyzer Configuration
```python
# examples/custom_analyzer_config.py
import asyncio
from mcpscanner.core.scanner import Scanner
from mcpscanner.core.analyzers.behavioral.code_analyzer import BehavioralCodeAnalyzer
from mcpscanner.core.analyzers.llm_analyzer import LLMAnalyzer
from mcpscanner.config.config import Config

async def main():
    # Custom configuration
    config = Config(
        llm_api_key="your-api-key",
        llm_model="gpt-4o",
        llm_base_url="https://custom-endpoint.com",
        llm_timeout=60,
        llm_max_retries=5,
        max_file_size_bytes=2_000_000,  # 2MB
        max_function_size_bytes=100_000  # 100KB
    )
    
    scanner = Scanner(config)
    
    # Scan with custom config
    results = await scanner.scan_local_code(
        path="/path/to/code",
        analyzers=["behavioral", "llm"]
    )
    
    print(f"Scan complete: {len(results)} findings")

if __name__ == "__main__":
    asyncio.run(main())
```

### 5. Output Processing Examples

#### Process and Filter Results
```python
# examples/output_processing.py
import asyncio
from mcpscanner.core.scanner import Scanner
from mcpscanner.config.config import Config

async def main():
    config = Config(
        llm_api_key="your-api-key",
        llm_model="gpt-4o"
    )
    
    scanner = Scanner(config)
    results = await scanner.scan_local_code(
        path="/path/to/code",
        analyzers=["behavioral", "llm", "yara"]
    )
    
    # Filter by severity
    high_severity = [
        r for r in results 
        if any(f.severity == "HIGH" for f in r.findings)
    ]
    
    print(f"High severity findings: {len(high_severity)}")
    
    # Group by threat category
    by_category = {}
    for result in results:
        for finding in result.findings:
            category = finding.threat_category
            if category not in by_category:
                by_category[category] = []
            by_category[category].append(finding)
    
    print("\nFindings by category:")
    for category, findings in by_category.items():
        print(f"  {category}: {len(findings)}")
    
    # Export to JSON
    import json
    output = {
        "total_findings": len(results),
        "high_severity": len(high_severity),
        "by_category": {k: len(v) for k, v in by_category.items()}
    }
    
    with open("scan_results.json", "w") as f:
        json.dump(output, f, indent=2)

if __name__ == "__main__":
    asyncio.run(main())
```

### 6. Batch Scanning Examples

#### Scan Multiple Servers
```python
# examples/batch_scanning.py
import asyncio
from mcpscanner.core.scanner import Scanner
from mcpscanner.config.config import Config

async def scan_server(scanner, server_url):
    """Scan a single server"""
    try:
        results = await scanner.scan_remote_server(
            server_url=server_url,
            analyzers=["llm", "yara"]
        )
        return server_url, results, None
    except Exception as e:
        return server_url, None, str(e)

async def main():
    config = Config(
        llm_api_key="your-api-key",
        llm_model="gpt-4o"
    )
    
    scanner = Scanner(config)
    
    # List of servers to scan
    servers = [
        "https://server1.example.com/mcp",
        "https://server2.example.com/mcp",
        "https://server3.example.com/mcp"
    ]
    
    # Scan all servers concurrently
    tasks = [scan_server(scanner, url) for url in servers]
    results = await asyncio.gather(*tasks)
    
    # Process results
    for server_url, scan_results, error in results:
        if error:
            print(f"❌ {server_url}: {error}")
        else:
            finding_count = sum(len(r.findings) for r in scan_results)
            print(f"✅ {server_url}: {finding_count} findings")

if __name__ == "__main__":
    asyncio.run(main())
```

### 7. CLI Examples

#### Basic CLI Usage
```bash
# Scan remote server
uv run mcp-scanner remote --server-url https://example.com/mcp

# Scan local code
uv run mcp-scanner behavioral /path/to/mcp-server

# Scan with specific analyzers
uv run mcp-scanner --analyzers llm,yara remote --server-url https://example.com/mcp

# Save output to file
uv run mcp-scanner --output results.json behavioral /path/to/code

# Use detailed format
uv run mcp-scanner --format detailed behavioral /path/to/code
```

#### Advanced CLI Usage
```bash
# Scan stdio server
uv run mcp-scanner stdio --stdio-command npx --stdio-args "-y,@modelcontextprotocol/server-filesystem"

# Scan from config file
uv run mcp-scanner config --config-path ~/.config/mcp/config.json

# Scan known config locations
uv run mcp-scanner known-configs

# Scan prompts
uv run mcp-scanner prompts --server-url https://example.com/mcp

# Scan resources
uv run mcp-scanner resources --server-url https://example.com/mcp

# Scan instructions
uv run mcp-scanner instructions --server-url https://example.com/mcp
```

## Writing New Examples

### Guidelines

1. **Keep Examples Simple**: Focus on one concept per example
2. **Include Comments**: Explain what each section does
3. **Handle Errors**: Show proper error handling
4. **Use Realistic Data**: Use realistic server URLs and paths
5. **Test Examples**: Ensure examples actually work
6. **Document Requirements**: List any prerequisites (API keys, etc.)

### Example Template

```python
"""
Example: [Brief description]

This example demonstrates [what it demonstrates].

Requirements:
- MCP Scanner installed: `uv pip install -e .`
- LLM API key: Set MCP_SCANNER_LLM_API_KEY environment variable
- [Any other requirements]

Usage:
    python examples/example_name.py
"""

import asyncio
from mcpscanner.core.scanner import Scanner
from mcpscanner.config.config import Config

async def main():
    """Main function demonstrating [feature]"""
    
    # 1. Setup configuration
    config = Config(
        llm_api_key="your-api-key",
        llm_model="gpt-4o"
    )
    
    # 2. Create scanner
    scanner = Scanner(config)
    
    # 3. Perform scan
    results = await scanner.scan_remote_server(
        server_url="https://example.com/mcp",
        analyzers=["behavioral", "llm"]
    )
    
    # 4. Process results
    print(f"Scan complete: {len(results)} findings")
    for result in results:
        print(f"- {result.tool_name}: {len(result.findings)} findings")

if __name__ == "__main__":
    asyncio.run(main())
```

## Example Server Directories

### `example-bearer-server/`

Example MCP server with bearer token authentication for testing authentication flows.

### `example-malicious-servers/`

Collection of intentionally vulnerable MCP servers for testing scanner detection capabilities:
- Code execution vulnerabilities
- Injection attacks
- Data exfiltration
- SSRF vulnerabilities
- Tool poisoning

**⚠️ WARNING**: These servers are intentionally insecure. Do NOT use in production.

### `example-oauth-server-clients/`

Example OAuth integration for MCP servers demonstrating:
- OAuth 2.0 flow
- Token management
- Refresh token handling

## Common Patterns

### Pattern 1: Environment-Based Configuration

```python
import os
from mcpscanner.config.config import Config

config = Config(
    llm_api_key=os.getenv("MCP_SCANNER_LLM_API_KEY"),
    llm_model=os.getenv("MCP_SCANNER_LLM_MODEL", "gpt-4o"),
    api_key=os.getenv("MCP_SCANNER_API_KEY")
)
```

### Pattern 2: Conditional Analyzer Selection

```python
analyzers = ["yara"]  # Always include YARA (fast)

if config.llm_api_key:
    analyzers.extend(["behavioral", "llm"])

if config.api_key:
    analyzers.append("api")

results = await scanner.scan_local_code(path, analyzers=analyzers)
```

### Pattern 3: Progress Reporting

```python
from tqdm import tqdm

servers = ["url1", "url2", "url3"]
results = []

for server in tqdm(servers, desc="Scanning servers"):
    result = await scanner.scan_remote_server(server, analyzers=["llm"])
    results.append(result)
```

### Pattern 4: Result Aggregation

```python
all_findings = []
for tool_result in results:
    all_findings.extend(tool_result.findings)

# Count by severity
severity_counts = {}
for finding in all_findings:
    severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1

print(f"HIGH: {severity_counts.get('HIGH', 0)}")
print(f"MEDIUM: {severity_counts.get('MEDIUM', 0)}")
print(f"LOW: {severity_counts.get('LOW', 0)}")
```

## Testing Examples

Before adding an example to the repository:

1. **Test it works**: Run the example and verify it produces expected output
2. **Test error cases**: Verify error handling works correctly
3. **Document requirements**: List all prerequisites clearly
4. **Add comments**: Explain non-obvious code
5. **Follow style guide**: Use consistent formatting

## Common Issues

### Issue 1: Import Errors
**Problem**: `ModuleNotFoundError: No module named 'mcpscanner'`
**Solution**: Install package: `uv pip install -e .` or use `uv run python examples/example.py`

### Issue 2: Missing API Keys
**Problem**: `ConfigurationError: LLM API key required`
**Solution**: Set environment variable: `export MCP_SCANNER_LLM_API_KEY=your-key`

### Issue 3: Async Errors
**Problem**: `RuntimeError: asyncio.run() cannot be called from a running event loop`
**Solution**: Use `await` instead of `asyncio.run()` if already in async context

## Contributing Examples

When contributing new examples:

1. Follow the example template above
2. Add clear documentation at the top
3. Include error handling
4. Test thoroughly
5. Add to this guide's table of contents
6. Submit PR with description of what the example demonstrates

---

**Last Updated**: December 2025
**Maintained By**: Cisco AI Defense Team
