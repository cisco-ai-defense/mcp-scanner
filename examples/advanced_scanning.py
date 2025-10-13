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
Advanced example script for MCP Scanner SDK with customization options.

This example demonstrates:
1. Using different endpoints
2. Generating different output formats (text, JSON)
3. Filtering results
4. Saving results to a file

Usage:
    python advanced_scanning.py <server_url> [--api-key=API_KEY] [--endpoint-url=URL] [--output=FORMAT] [--severity=LEVEL] [--output-file=FILE]

Options:
    --endpoint-url=URL  Endpoint URL to use. Overrides the default.
    --output=FORMAT     Output format (text, json). Default: text
    --severity=LEVEL    Filter by severity (high, medium, low). Default: all
    --output-file=FILE  Save results to file. Default: None (print to stdout)

Example:
    python advanced_scanning.py https://mcp-server.example.com --api-key=your_api_key --endpoint-url=https://eu.api.inspect.aidefense.security.cisco.com/api/v1 --output=json --severity=high
"""

import argparse
import asyncio
import json
import sys

from mcpscanner import Config, Scanner
from mcpscanner.core.result import filter_results_by_severity, process_scan_results


# Helper functions for output formatting
def format_text_output(results, severity_filter=None):
    """Format scan results as text."""
    output = []

    # Filter results by severity if needed
    if severity_filter:
        results = filter_results_by_severity(results, severity_filter)

    # Process results to get statistics
    stats = process_scan_results(results)

    output.append(f"Scan completed. Found {stats['total_tools']} tools.")
    output.append(f"Safe tools: {stats['safe_tools']}")
    output.append(f"Vulnerable tools: {stats['vulnerable_tools']}")

    # Add severity counts
    if stats["vulnerable_tools"] > 0:
        output.append("\nVulnerability severity breakdown:")
        for severity, count in stats["severity_counts"].items():
            if count > 0:
                output.append(f"  {severity.upper()}: {count}")

    # Add threat type counts if available
    if stats["threat_types"]:
        output.append("\nThreat type breakdown:")
        for threat_type, count in stats["threat_types"].items():
            output.append(f"  {threat_type}: {count}")

    # Print details for vulnerable tools
    vulnerable_tools = [r for r in results if not r.is_safe]
    if vulnerable_tools:
        output.append("\nDetails for vulnerable tools:")
        for result in vulnerable_tools:
            output.append(f"\nTool: {result.tool_name}")
            output.append(f"Description: {result.tool_description}")
            output.append(f"Status: {result.status}")
            output.append(f"Findings: {len(result.findings)}")

            for i, finding in enumerate(result.findings, 1):
                output.append(f"  Finding #{i}:")
                output.append(f"    Severity: {finding.severity}")
                output.append(f"    Summary: {finding.summary}")
                output.append(f"    Analyzer: {finding.analyzer}")
                if (
                    hasattr(finding, "details")
                    and finding.details
                    and "threat_type" in finding.details
                ):
                    output.append(f"    Threat Type: {finding.details['threat_type']}")

    return "\n".join(output)


def format_json_output(results, severity_filter=None):
    """Format scan results as JSON."""
    # Filter results by severity if needed
    if severity_filter:
        results = filter_results_by_severity(results, severity_filter)

    # Process results to get statistics
    stats = process_scan_results(results)

    output = {
        "scan_summary": {
            "total_tools": stats["total_tools"],
            "safe_tools": stats["safe_tools"],
            "vulnerable_tools": stats["vulnerable_tools"],
            "severity_counts": stats["severity_counts"],
            "threat_types": stats["threat_types"],
        },
        "results": [],
    }

    for result in results:
        if not result.is_safe:
            findings_list = []
            for finding in result.findings:
                finding_data = {
                    "severity": finding.severity,
                    "summary": finding.summary,
                    "analyzer": finding.analyzer,
                }

                # Add details if available
                if hasattr(finding, "details") and finding.details:
                    finding_data["details"] = finding.details
                    # Extract threat_type to top level if available
                    if "threat_type" in finding.details:
                        finding_data["threat_type"] = finding.details["threat_type"]

                findings_list.append(finding_data)

            output["results"].append(
                {
                    "tool_name": result.tool_name,
                    "tool_description": result.tool_description,
                    "status": result.status,
                    "findings": findings_list,
                }
            )

    return json.dumps(output, indent=2)


async def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Advanced MCP Scanner")
    parser.add_argument("server_url", help="URL of the MCP server")
    parser.add_argument("--api-key", help="API key for Cisco AI Defense", default="")
    parser.add_argument("--endpoint-url", help="Endpoint URL to use")
    parser.add_argument(
        "--output", choices=["text", "json"], default="text", help="Output format"
    )
    parser.add_argument(
        "--severity", choices=["high", "medium", "low"], help="Filter by severity"
    )
    parser.add_argument("--output-file", help="Save results to file")

    args = parser.parse_args()

    # Create configuration with specified endpoint URL
    config = Config(api_key=args.api_key, endpoint_url=args.endpoint_url)

    # Create scanner
    scanner = Scanner(config)

    try:
        # Scan all tools on the server
        print(f"Scanning all tools on server {args.server_url}")
        results = await scanner.scan_remote_server_tools(args.server_url)

        # Format output based on selected format
        if args.output == "json":
            formatted_output = format_json_output(results, args.severity)
        else:  # text
            formatted_output = format_text_output(results, args.severity)

        # Output results
        if args.output_file:
            with open(args.output_file, "w") as f:
                f.write(formatted_output)
            print(f"Results saved to {args.output_file}")
        else:
            print("\n" + formatted_output)

    except ValueError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")


def cli_entry_point():
    """Entry point for command-line interface."""
    asyncio.run(main())


if __name__ == "__main__":
    cli_entry_point()
