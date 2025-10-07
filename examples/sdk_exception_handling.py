#!/usr/bin/env python3
"""Example: MCP Scanner SDK with proper exception handling.

This example demonstrates how to use the MCP Scanner SDK as a library
with proper exception handling for different error scenarios.
"""

import asyncio
from mcpscanner import (
    Scanner,
    Config,
    MCPAuthenticationError,
    MCPServerNotFoundError,
    MCPConnectionError,
    MCPScannerError,
    AnalyzerEnum,
)


async def scan_with_error_handling(server_url: str):
    """Scan an MCP server with comprehensive error handling."""
    
    config = Config()
    scanner = Scanner(config)
    
    print(f"🔍 Scanning MCP server: {server_url}")
    
    try:
        # Use only YARA analyzer (doesn't require API key)
        results = await scanner.scan_remote_server_tools(
            server_url,
            analyzers=[AnalyzerEnum.YARA]
        )
        
        print(f"✅ Scan completed successfully!")
        print(f"📊 Found {len(results)} tools")
        
        for result in results:
            print(f"\n  Tool: {result.tool_name}")
            print(f"  Findings: {len(result.findings)}")
            if result.findings:
                print(f"  ⚠️  Security issues detected!")
        
        return results
        
    except MCPAuthenticationError as e:
        print(f"🔒 Authentication Error: {e}")
        print("💡 This server requires authentication.")
        print("   Use: --bearer-token <token> or configure OAuth")
        return []
        
    except MCPServerNotFoundError as e:
        print(f"❌ Server Not Found: {e}")
        print("💡 Please verify:")
        print("   • The URL is correct")
        print("   • The endpoint path exists")
        return []
        
    except MCPConnectionError as e:
        print(f"🔌 Connection Error: {e}")
        print("💡 Please check:")
        print("   • The server is running")
        print("   • Your internet connection")
        print("   • DNS resolution works")
        return []
        
    except MCPScannerError as e:
        print(f"⚠️  MCP Scanner Error: {e}")
        return []


async def main():
    """Run example scans with different scenarios."""
    
    print("=" * 60)
    print("MCP Scanner SDK - Exception Handling Examples")
    print("=" * 60)
    
    # Example 1: Server requiring authentication (401)
    print("\n\n📋 Example 1: Server requiring authentication")
    print("-" * 60)
    await scan_with_error_handling(
        "https://server.smithery.ai/@infranodus/mcp-server-infranodus/mcp"
    )
    
    # Example 2: Non-existent server (DNS failure)
    print("\n\n📋 Example 2: Non-existent server (DNS failure)")
    print("-" * 60)
    await scan_with_error_handling("https://test.alpic.ai/")
    
    # Note: Other error scenarios would be demonstrated with actual test servers
    # Example 3 would show 404 errors with appropriate test servers
    
    print("\n\n" + "=" * 60)
    print("Examples completed!")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
