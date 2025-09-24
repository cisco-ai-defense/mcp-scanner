#!/usr/bin/env python3
# Copyright 2025 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""
Explicit Auth Parameter Example for MCP Scanner

This example demonstrates how to use explicit Auth parameters with the MCP Scanner SDK
to have fine-grained control over authentication for each server connection.
"""

import asyncio
import os

from mcpscanner import Config, Scanner, Auth, AuthType, InMemoryTokenStorage


async def explicit_oauth_example():
    """Example using explicit Auth parameter with OAuth."""

    print("=== Explicit OAuth Authentication Example ===")

    # Create scanner with minimal config (no OAuth in config)
    config = Config(
        api_key=os.getenv("MCP_SCANNER_API_KEY"),
        llm_provider_api_key=os.getenv("OPENAI_API_KEY"),
    )
    scanner = Scanner(config)

    # Create explicit OAuth authentication
    auth = Auth.oauth(
        client_id=os.getenv("MCP_SCANNER_OAUTH_CLIENT_ID", "your_client_id"),
        client_secret=os.getenv("MCP_SCANNER_OAUTH_CLIENT_SECRET"),
        scopes=["user", "read:tools"],
        storage=InMemoryTokenStorage(),
    )

    server_url = "http://localhost:8001/mcp"

    print(f"Scanning with explicit OAuth: {server_url}")
    print(f"Auth enabled: {auth}")
    print(f"Auth type: {auth.type}")
    print(f"Is OAuth: {auth.is_oauth()}")

    try:
        # Pass explicit auth parameter - this takes priority over config
        results = await scanner.scan_remote_server_tools(
            server_url,
            auth=auth,  # Explicit auth parameter
            api_scan=True,
            yara_scan=True,
            llm_scan=True,
        )

        print(f"\nScan completed! Found {len(results)} tools.")

        for result in results:
            print(f"\nTool: {result.tool_name}")
            print(f"Safe: {result.is_safe}")
            if not result.is_safe:
                for vuln in result.vulnerabilities:
                    print(f"  - {vuln.severity}: {vuln.summary}")

    except Exception as e:
        print(f"Error: {e}")


async def conditional_auth_example():
    """Example showing conditional authentication based on server."""

    print("\n=== Conditional Authentication Example ===")

    config = Config(
        api_key=os.getenv("MCP_SCANNER_API_KEY"),
        llm_provider_api_key=os.getenv("OPENAI_API_KEY"),
    )
    scanner = Scanner(config)

    servers = [
        {
            "url": "http://localhost:8001/mcp",
            "auth": Auth.oauth(
                client_id="oauth_client_id", scopes=["user", "read:tools"]
            ),
            "name": "OAuth Server",
        },
        {
            "url": "http://localhost:8002/mcp",
            "auth": Auth(enabled=False),  # Explicitly disable auth
            "name": "Public Server",
        },
        {
            "url": "http://localhost:8003/mcp",
            "auth": None,  # Use config-based auth (if any)
            "name": "Config-based Server",
        },
    ]

    for server in servers:
        print(f"\nScanning {server['name']}: {server['url']}")

        if server["auth"] is not None:
            print(
                f"Using explicit auth: {server['auth'].enabled} (type: {server['auth'].type})"
            )
        else:
            print("Using config-based authentication")

        try:
            # Each server can have different auth configuration
            results = await scanner.scan_remote_server_tools(
                server["url"],
                auth=server["auth"],  # Different auth per server
                api_scan=True,
                yara_scan=False,  # Skip YARA for faster demo
                llm_scan=False,  # Skip LLM for faster demo
            )

            print(f"  ✅ Success: {len(results)} tools found")

        except Exception as e:
            print(f"  ❌ Error: {e}")


async def auth_priority_example():
    """Example showing auth priority: explicit Auth > config OAuth."""

    print("\n=== Authentication Priority Example ===")

    # Config with OAuth settings
    config = Config(
        oauth_client_id="config_client_id",
        oauth_client_secret="config_secret",
        oauth_scopes=["config_scope"],
    )
    scanner = Scanner(config)

    server_url = "http://localhost:8001/mcp"

    print("1. Using config-based OAuth (no explicit auth):")
    try:
        results = await scanner.scan_remote_server_tools(
            server_url,
            # No auth parameter - uses config OAuth
            api_scan=False,
            yara_scan=True,
            llm_scan=False,
        )
        print(f"   ✅ Config OAuth used: {len(results)} tools")
    except Exception as e:
        print(f"   ❌ Config OAuth failed: {e}")

    print("\n2. Explicit Auth overrides config:")
    explicit_auth = Auth.oauth(
        client_id="explicit_client_id", scopes=["explicit_scope"]
    )

    try:
        results = await scanner.scan_remote_server_tools(
            server_url,
            auth=explicit_auth,  # This takes priority over config
            api_scan=False,
            yara_scan=True,
            llm_scan=False,
        )
        print(f"   ✅ Explicit OAuth used: {len(results)} tools")
    except Exception as e:
        print(f"   ❌ Explicit OAuth failed: {e}")

    print("\n3. Explicitly disable auth:")
    no_auth = Auth(enabled=False)

    try:
        results = await scanner.scan_remote_server_tools(
            server_url,
            auth=no_auth,  # Explicitly disable auth
            api_scan=False,
            yara_scan=True,
            llm_scan=False,
        )
        print(f"   ✅ No auth used: {len(results)} tools")
    except Exception as e:
        print(f"   ❌ No auth failed: {e}")


async def custom_oauth_handlers_example():
    """Example with custom OAuth handlers in explicit Auth."""

    print("\n=== Custom OAuth Handlers Example ===")

    async def custom_redirect_handler(auth_url: str) -> None:
        print(f"\n🔐 Custom Redirect Handler")
        print(f"Please visit: {auth_url}")
        print("This is a custom redirect handler!")

    async def custom_callback_handler() -> tuple[str, str | None]:
        print("\n📞 Custom Callback Handler")
        callback_url = input("Enter callback URL: ")
        # Simple parsing for demo
        if "code=" in callback_url:
            code = callback_url.split("code=")[1].split("&")[0]
            return code, None
        raise ValueError("No code found")

    # Create Auth with custom handlers
    auth = Auth.oauth(
        client_id="demo_client_id",
        scopes=["user"],
        redirect_handler=custom_redirect_handler,
        callback_handler=custom_callback_handler,
        storage=InMemoryTokenStorage(),
    )

    config = Config()
    scanner = Scanner(config)

    print("Auth with custom handlers created!")
    print(f"Redirect handler: {auth.redirect_handler}")
    print(f"Callback handler: {auth.callback_handler}")

    # This would use the custom handlers during OAuth flow
    print("Custom handlers would be used during actual OAuth flow.")


async def main():
    """Main function to run explicit auth examples."""

    print("MCP Scanner Explicit Auth Parameter Examples")
    print("=" * 60)

    examples = [
        ("1", "Explicit OAuth Authentication", explicit_oauth_example),
        ("2", "Conditional Authentication", conditional_auth_example),
        ("3", "Authentication Priority", auth_priority_example),
        ("4", "Custom OAuth Handlers", custom_oauth_handlers_example),
        ("5", "Run All Examples", None),
        ("6", "Exit", None),
    ]

    print("\nAvailable examples:")
    for num, name, _ in examples:
        print(f"{num}. {name}")

    choice = input("\nEnter your choice (1-6): ").strip()

    if choice == "1":
        await explicit_oauth_example()
    elif choice == "2":
        await conditional_auth_example()
    elif choice == "3":
        await auth_priority_example()
    elif choice == "4":
        await custom_oauth_handlers_example()
    elif choice == "5":
        print("\nRunning all examples...")
        await explicit_oauth_example()
        await conditional_auth_example()
        await auth_priority_example()
        await custom_oauth_handlers_example()
    elif choice == "6":
        print("Goodbye!")
    else:
        print("Invalid choice. Please run the script again.")


if __name__ == "__main__":
    asyncio.run(main())
