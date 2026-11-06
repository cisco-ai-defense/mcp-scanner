# Programmatic Usage
For advanced use cases, you can use the MCP Scanner programmatically:

```python
import asyncio
from mcpscanner import Config, Scanner
from mcpscanner.core.models import AnalyzerEnum

async def main():
    # Create configuration with your API keys
    config = Config(
        api_key="your_cisco_api_key",
        llm_provider_api_key="your_llm_api_key"
    )

    # Create scanner
    scanner = Scanner(config)

    # Scan all tools on a remote server
    tool_results = await scanner.scan_remote_server_tools(
        "https://mcp.deepwiki.com/mcp",
        analyzers=[AnalyzerEnum.API, AnalyzerEnum.YARA, AnalyzerEnum.LLM]
    )

    # Print tool results
    for result in tool_results:
        print(f"Tool: {result.tool_name}, Safe: {result.is_safe}")

    # Scan all prompts on a server
    prompt_results = await scanner.scan_remote_server_prompts(
        "http://127.0.0.1:8000/mcp",
        analyzers=[AnalyzerEnum.LLM]
    )

    # Print prompt results
    for result in prompt_results:
        print(f"Prompt: {result.prompt_name}, Safe: {result.is_safe}")

    # Scan all resources on a server
    resource_results = await scanner.scan_remote_server_resources(
        "http://127.0.0.1:8000/mcp",
        analyzers=[AnalyzerEnum.LLM],
        allowed_mime_types=["text/plain", "text/html"]
    )

    # Print resource results
    for result in resource_results:
        print(f"Resource: {result.resource_name}, Safe: {result.is_safe}, Status: {result.status}")

    # Scan server instructions
    instructions_result = await scanner.scan_remote_server_instructions(
        "http://127.0.0.1:8000/mcp",
        analyzers=[AnalyzerEnum.LLM]
    )

    # Print instructions result
    print(f"Instructions: Safe: {instructions_result.is_safe}, Findings: {len(instructions_result.findings)}")

# Run the scanner
asyncio.run(main())
```

## Paginated Server Lists

Tool and prompt scans follow MCP pagination for both remote and stdio servers.
Remote resource scans also follow pagination. This implementation supports the
MCP SDK 2.x dependency and protocol negotiation used by the scanner.

Bulk scans discover every listed item before analyzing the inventory. A scan
for a specific tool, prompt, or resource also finishes discovery before analysis
so a later duplicate cannot hide behind a benign first match. Duplicate names
for the requested tool or prompt, or duplicate URIs for the requested resource,
raise `mcpscanner.core.pagination.MCPPaginationError`. Named scans retain their
single-result API; they do not select an arbitrary duplicate. Bulk scans still
analyze all listed entries.

The scanner forwards opaque cursor values without changing them, including empty
strings, and continues past empty pages with a cursor. It reads SDK 2's
`next_cursor` attribute (with a legacy `nextCursor` fallback) and treats an
explicit `None` as the final page. Missing cursor fields are errors. Existing
prompt and resource content budgets apply across the combined inventory.

Discovery limits are configured through environment variables, set before
importing the scanner:

| Environment variable | Default | Meaning |
| --- | --- | --- |
| `MCP_SCANNER_MCP_LIST_PAGE_TIMEOUT_SECONDS` | `30` | Finite, positive timeout per list request |
| `MCP_SCANNER_MAX_MCP_LIST_PAGES` | `1000` | Positive maximum pages per list operation |
| `MCP_SCANNER_MAX_MCP_LIST_ITEMS` | `10000` | Positive maximum items per list operation |

The list timeout applies to **every page, including the first**. This adds a
scanner-level timeout to the original single-page request; it is intentional
and independent of `MCP_SCANNER_MCP_CONTENT_READ_TIMEOUT_SECONDS`, which controls
prompt/resource body reads. It is not a deadline for the whole scan. Named scans
now inspect subsequent pages and are subject to the same discovery limits.

Repeated cursors, missing/invalid cursor fields, exceeded limits, request
timeouts, and later-page request failures raise `MCPPaginationError`. First-page
MCP protocol errors retain their existing unsupported-capability handling;
already classified `MCPConnectionError` exceptions (including authentication
and endpoint-not-found subclasses) retain their type on every page. Other
request errors are wrapped with their original cause. Cancellation
propagates unchanged, and named-scan iterators are explicitly closed.

These errors propagate from individual server scan methods instead of returning
a successful partial result. `MCPPaginationError` maps to HTTP **502** in the
REST API. Configuration scans retain their existing behavior of
recording a server error and continuing with the other servers.

Invalid page/item limits or list-page timeouts raise `MCPConfigurationError`
before the first list request. These local configuration failures map to HTTP
**500**, rather than the **404** reserved for missing items. Classified
authentication failures retain HTTP **401**, and endpoint-not-found failures
retain HTTP **404**.

## Advanced Examples

### Scanning a Specific Tool

```python
import asyncio
from mcpscanner import Config, Scanner
from mcpscanner.core.models import AnalyzerEnum

async def main():
    config = Config(
        api_key="your_cisco_api_key",
        llm_provider_api_key="your_llm_api_key"
    )

    scanner = Scanner(config)

    # Scan a specific tool
    result = await scanner.scan_remote_server_tool(
        "https://mcp.deepwiki.com/mcp",
        "add",  # tool name
        analyzers=[AnalyzerEnum.API, AnalyzerEnum.YARA, AnalyzerEnum.LLM]
    )

    print(f"Tool: {result.tool_name}, Safe: {result.is_safe}")
    if not result.is_safe:
        print(f"Findings: {len(result.findings)}")

asyncio.run(main())
```

### Scanning a Specific Prompt

```python
import asyncio
from mcpscanner import Config, Scanner
from mcpscanner.core.models import AnalyzerEnum

async def main():
    config = Config(llm_provider_api_key="your_llm_api_key")
    scanner = Scanner(config)

    # Scan a specific prompt
    result = await scanner.scan_remote_server_prompt(
        "http://127.0.0.1:8000/mcp",
        "greet_user",  # prompt name
        analyzers=[AnalyzerEnum.LLM]
    )

    print(f"Prompt: {result.prompt_name}")
    print(f"Description: {result.prompt_description}")
    print(f"Safe: {result.is_safe}")

    if not result.is_safe:
        for finding in result.findings:
            print(f"  - {finding.severity}: {finding.summary}")

            # Access MCP Taxonomy information
            if hasattr(finding, 'mcp_taxonomy') and finding.mcp_taxonomy:
                taxonomy = finding.mcp_taxonomy
                print(f"    Technique: {taxonomy.get('aitech')} - {taxonomy.get('aitech_name')}")
                print(f"    Sub-Technique: {taxonomy.get('aisubtech')} - {taxonomy.get('aisubtech_name')}")
                print(f"    Description: {taxonomy.get('description')}")

asyncio.run(main())
```

### Scanning a Specific Resource

```python
import asyncio
from mcpscanner import Config, Scanner
from mcpscanner.core.models import AnalyzerEnum

async def main():
    config = Config(llm_provider_api_key="your_llm_api_key")
    scanner = Scanner(config)

    # Scan a specific resource
    result = await scanner.scan_remote_server_resource(
        "http://127.0.0.1:8000/mcp",
        "file://test/document.txt",  # resource URI
        analyzers=[AnalyzerEnum.LLM],
        allowed_mime_types=["text/plain", "text/html"]
    )

    print(f"Resource: {result.resource_name}")
    print(f"URI: {result.resource_uri}")
    print(f"MIME Type: {result.resource_mime_type}")
    print(f"Status: {result.status}")
    print(f"Safe: {result.is_safe}")

    if result.status == "skipped":
        print("Resource was skipped (unsupported MIME type)")
    elif not result.is_safe:
        for finding in result.findings:
            print(f"  - {finding.severity}: {finding.summary}")

asyncio.run(main())
```

### Scanning Server Instructions

Server instructions are returned during MCP session setup (`DiscoverResult` on mcp 2.0 servers, `InitializeResult` on legacy servers) and contain usage guidelines, security notes, and configuration details.

```python
import asyncio
from mcpscanner import Config, Scanner
from mcpscanner.core.models import AnalyzerEnum

async def main():
    config = Config(llm_provider_api_key="your_llm_api_key")
    scanner = Scanner(config)

    # Scan server instructions
    result = await scanner.scan_remote_server_instructions(
        "http://127.0.0.1:8000/mcp",
        analyzers=[AnalyzerEnum.LLM]
    )

    print(f"Server: {result.server_name}")
    print(f"Protocol Version: {result.protocol_version}")
    print(f"Status: {result.status}")

    if result.instructions:
        print(f"Instructions (preview): {result.instructions[:100]}...")
    else:
        print("No instructions provided by server")

    print(f"Safe: {result.is_safe}")

    if result.status == "completed" and not result.is_safe:
        print(f"\nSecurity Findings ({len(result.findings)}):")
        for finding in result.findings:
            print(f"  - {finding.severity}: {finding.summary}")

            # Access MCP Taxonomy information
            if hasattr(finding, 'mcp_taxonomy') and finding.mcp_taxonomy:
                taxonomy = finding.mcp_taxonomy
                print(f"    Technique: {taxonomy.get('aitech')} - {taxonomy.get('aitech_name')}")
                if taxonomy.get('aisubtech'):
                    print(f"    Sub-Technique: {taxonomy.get('aisubtech')} - {taxonomy.get('aisubtech_name')}")
    elif result.status == "skipped":
        print("Server does not provide instructions field")

asyncio.run(main())
```

### VirusTotal File/Directory Scanning

```python
from mcpscanner.core.analyzers.virustotal_analyzer import VirusTotalAnalyzer

# Create VirusTotal analyzer
vt = VirusTotalAnalyzer(
    api_key="your_virustotal_api_key",
    enabled=True,
    upload_files=False,  # privacy-friendly: hash-only lookups
    max_files=10,
)

# Scan a single file
finding = vt.analyze_file("/path/to/suspicious_file.exe")
if finding:
    print(f"MALWARE: {finding.severity} - {finding.summary}")
else:
    print("File is clean or not in VT database")

# Scan a directory
findings = vt.analyze_directory("/path/to/mcp_server_package/")
for f in findings:
    print(f"{f.severity}: {f.summary}")
    if f.details:
        print(f"  File: {f.details.get('file_path')}")

# Check scan summary
summary = vt.last_scan_summary
print(f"Scanned: {summary['scanned']}, Malicious: {summary['malicious']}, Clean: {summary['clean']}")
```

### Scanning with Authentication

```python
import asyncio
from mcpscanner import Config, Scanner
from mcpscanner.core.auth import Auth, AuthType
from mcpscanner.core.models import AnalyzerEnum

async def main():
    config = Config(api_key="your_cisco_api_key")
    scanner = Scanner(config)

    # Create authentication configuration
    auth = Auth(
        auth_type=AuthType.BEARER,
        bearer_token="your_bearer_token"
    )

    # Scan with authentication
    results = await scanner.scan_remote_server_tools(
        "https://protected-mcp-server.com/mcp",
        auth=auth,
        analyzers=[AnalyzerEnum.API, AnalyzerEnum.YARA]
    )

    for result in results:
        print(f"Tool: {result.tool_name}, Safe: {result.is_safe}")

asyncio.run(main())
```

More examples can be found in the [examples](../examples/) directory.
