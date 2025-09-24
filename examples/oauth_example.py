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
OAuth Authentication Example for MCP Scanner

This example demonstrates how to use OAuth authentication with the MCP Scanner SDK
to connect to MCP servers that require OAuth authentication.
"""

import asyncio
import os
from typing import List

from mcpscanner import Config, Scanner, InMemoryTokenStorage, OAuthHandler


async def oauth_scanning_example():
    """Example of scanning an MCP server with OAuth authentication."""

    # Configure OAuth parameters
    config = Config(
        # Standard API keys (optional)
        api_key=os.getenv("MCP_SCANNER_API_KEY"),
        llm_provider_api_key=os.getenv("OPENAI_API_KEY"),
        # OAuth configuration
        oauth_client_id=os.getenv("MCP_SCANNER_OAUTH_CLIENT_ID"),
        oauth_client_secret=os.getenv("MCP_SCANNER_OAUTH_CLIENT_SECRET"),
        oauth_scopes=["user", "read:tools"],  # Customize based on server requirements
    )

    # Create scanner with OAuth support
    scanner = Scanner(config)

    # Example server URL (replace with your OAuth-enabled MCP server)
    server_url = "http://localhost:8001/mcp"

    print(f"Scanning OAuth-enabled MCP server: {server_url}")
    print("Note: You may be prompted to authorize the application in your browser.")

    try:
        # Scan all tools on the server
        # The scanner will automatically handle OAuth flow if configured
        results = await scanner.scan_remote_server_tools(
            server_url, api_scan=True, yara_scan=True, llm_scan=True
        )

        print(f"\nScan completed! Found {len(results)} tools.")

        # Display results
        for result in results:
            print(f"\nTool: {result.tool_name}")
            print(f"Status: {result.status}")
            print(f"Safe: {result.is_safe}")

            if not result.is_safe:
                print("Vulnerabilities found:")
                for vuln in result.vulnerabilities:
                    print(f"  - {vuln.severity} ({vuln.analyzer}): {vuln.summary}")

    except Exception as e:
        print(f"Error during OAuth scanning: {e}")
        print(
            "Make sure your OAuth configuration is correct and the server supports OAuth."
        )


async def custom_oauth_handler_example():
    """Example with custom OAuth handlers for advanced use cases."""

    class CustomOAuthHandler(OAuthHandler):
        """Custom OAuth handler with enhanced logging."""

        async def handle_redirect(self, auth_url: str) -> None:
            """Custom redirect handler with enhanced user experience."""
            print("\n" + "=" * 60)
            print("🔐 OAUTH AUTHORIZATION REQUIRED")
            print("=" * 60)
            print(f"Please visit the following URL to authorize the application:")
            print(f"\n{auth_url}\n")
            print("After authorizing, you'll be redirected to a callback URL.")
            print("Copy the entire callback URL and paste it when prompted.")
            print("=" * 60)

        async def handle_callback(self) -> tuple[str, str | None]:
            """Custom callback handler with input validation."""
            while True:
                callback_url = input("\nPaste the callback URL here: ").strip()

                if not callback_url:
                    print("❌ Empty URL. Please try again.")
                    continue

                if "code=" not in callback_url:
                    print(
                        "❌ Invalid callback URL (missing authorization code). Please try again."
                    )
                    continue

                try:
                    # Parse the callback URL
                    from urllib.parse import parse_qs, urlparse

                    params = parse_qs(urlparse(callback_url).query)

                    if "code" not in params:
                        print("❌ Authorization code not found. Please try again.")
                        continue

                    code = params["code"][0]
                    state = params.get("state", [None])[0]

                    print("✅ Authorization code received successfully!")
                    return code, state

                except Exception as e:
                    print(f"❌ Error parsing callback URL: {e}. Please try again.")
                    continue

    # Configuration with custom OAuth handler
    config = Config(
        oauth_client_id=os.getenv("MCP_SCANNER_OAUTH_CLIENT_ID"),
        oauth_client_secret=os.getenv("MCP_SCANNER_OAUTH_CLIENT_SECRET"),
        oauth_scopes=["user", "read:tools", "read:resources"],
    )

    # Create custom OAuth handler
    oauth_handler = CustomOAuthHandler(config)

    # Create OAuth provider with custom handlers
    server_url = "http://localhost:8001"
    oauth_provider = oauth_handler.create_oauth_provider(
        server_url=server_url,
        storage=InMemoryTokenStorage(),
    )

    print("Custom OAuth handler configured successfully!")
    print(
        "This example shows how to customize the OAuth flow for better user experience."
    )


def setup_environment_variables():
    """Helper function to show required environment variables."""

    required_vars = {
        "MCP_SCANNER_OAUTH_CLIENT_ID": "Your OAuth client ID",
        "MCP_SCANNER_OAUTH_CLIENT_SECRET": "Your OAuth client secret",
        "MCP_SCANNER_API_KEY": "Cisco AI Defense API key (optional)",
        "OPENAI_API_KEY": "OpenAI API key for LLM analysis (optional)",
    }

    print("Required Environment Variables for OAuth:")
    print("=" * 50)

    missing_vars = []
    for var, description in required_vars.items():
        value = os.getenv(var)
        status = "✅ SET" if value else "❌ MISSING"
        print(f"{var}: {status}")
        print(f"  Description: {description}")

        if not value:
            missing_vars.append(var)
        print()

    if missing_vars:
        print("⚠️  Missing required environment variables:")
        for var in missing_vars:
            print(f"   export {var}='your_value_here'")
        print("\nSet these variables before running the OAuth example.")
        return False

    print("✅ All required environment variables are set!")
    return True


async def main():
    """Main function to run OAuth examples."""

    print("MCP Scanner OAuth Authentication Examples")
    print("=" * 50)

    # Check environment setup
    if not setup_environment_variables():
        return

    print("\nChoose an example to run:")
    print("1. Basic OAuth scanning")
    print("2. Custom OAuth handler")
    print("3. Exit")

    choice = input("\nEnter your choice (1-3): ").strip()

    if choice == "1":
        await oauth_scanning_example()
    elif choice == "2":
        await custom_oauth_handler_example()
    elif choice == "3":
        print("Goodbye!")
    else:
        print("Invalid choice. Please run the script again.")


if __name__ == "__main__":
    asyncio.run(main())
