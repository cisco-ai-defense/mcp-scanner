# Programmatic Usage
For advanced use cases, you can use the MCP Scanner programmatically:

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
        "https://mcp.deepwiki.com/mcp",
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

## Advanced Examples

### Scanning a Specific Tool

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
        "https://mcp.deepwiki.com/mcp",
        api_scan=True,    # Cisco AI Defense
        yara_scan=True,   # YARA rules
        llm_scan=True,
        tool_name = tool,
    )
    
    # Print results
    for result in results:
        print(f"Tool: {result.tool_name}, Safe: {result.is_safe}")

# Run the scanner
asyncio.run(main())
```

### Scanning All Tools on a Server

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
        "https://mcp.deepwiki.com/mcp",
        api_scan=True,    # Cisco AI Defense
        yara_scan=True,   # YARA rules
        llm_scan=True     # LLM analysis
    )
    
    # Print results
    for result in results:
        print(f"Tool: {result.tool_name}, Safe: {result.is_safe}")

# Run the scanner
asyncio.run(main())
    
    return results
```

More examples can be found in the [examples](../examples/) directory.
