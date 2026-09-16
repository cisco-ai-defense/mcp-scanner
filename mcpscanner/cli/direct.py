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

"""Programmatic single-server scan used by the CLI and by SDK callers."""

import json
import time
import traceback
from typing import Any, List, Optional

from mcpscanner import Scanner
from mcpscanner.core.models import AnalyzerEnum
from mcpscanner.core.report_generator import results_to_json
from mcpscanner.utils.logging_config import get_logger

from .config import _build_config

logger = get_logger(__name__)


async def scan_mcp_server_direct(
    server_url: str,
    analyzers: List[AnalyzerEnum],
    output_file: Optional[str] = None,
    verbose: bool = False,
    rules_path: Optional[str] = None,
    endpoint_url: Optional[str] = None,
) -> List[Any]:
    """
    Perform comprehensive security scanning of an MCP server using Scanner directly.

    Args:
        server_url: URL of the MCP server to scan
        analyzers: List of analyzers to run
        output_file: Optional file to save the scan results
        verbose: Whether to print verbose output
        rules_path: Optional custom path to YARA rules directory

    Returns:
        List of scan results
    """
    if verbose:
        enabled_analyzers = [analyzer.value.upper() for analyzer in analyzers]
        print(f"🔍 Scanning MCP server: {server_url}")
        print(
            f"   Analyzers: {', '.join(enabled_analyzers) if enabled_analyzers else 'None'}"
        )
        if rules_path:
            print(f"   Custom YARA Rules: {rules_path}")

    try:
        config = _build_config(analyzers, endpoint_url)
        scanner = Scanner(config, rules_dir=rules_path)

        # Scan all tools on the server
        start_time = time.time()
        results = await scanner.scan_remote_server_tools(
            server_url, auth=None, analyzers=analyzers
        )
        elapsed_time = time.time() - start_time

        if verbose:
            print(
                f"✅ Scan completed in {elapsed_time:.2f}s - Found {len(results)} tools"
            )

        # Normalize ScanResult objects
        json_results = await results_to_json(results)

        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(json_results, f, indent=2)
            if verbose:
                print(f"Results saved to {output_file}")

        return json_results

    except Exception as e:
        # Handle MCP-specific exceptions gracefully
        if e.__class__.__name__ in (
            "MCPConnectionError",
            "MCPAuthenticationError",
            "MCPServerNotFoundError",
        ):
            print(f"❌ Connection Error: {e}")
            if verbose:
                print("💡 Troubleshooting tips:")
                print(f"   • Make sure an MCP server is running at {server_url}")
                print("   • Verify the URL is correct (including protocol and port)")
                print("   • Check if the server is accessible from your network")
            return []
        # All other exceptions
        print(f"❌ Error scanning server: {e}")
        if verbose:
            traceback.print_exc()
        return []
