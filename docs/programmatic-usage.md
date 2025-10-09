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

# Run the scanner
asyncio.run(main())
```

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
