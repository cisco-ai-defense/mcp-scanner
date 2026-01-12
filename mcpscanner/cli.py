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


#!/usr/bin/env python3
"""
MCP Security Scanner

A comprehensive security scanning tool for Model Context Protocol (MCP) servers.
This tool analyzes MCP tools for potential security findings using multiple
analysis engines including API-based classification, YARA pattern matching,
and LLM-powered threat detection.
"""

import argparse
import asyncio
import json
import logging
import os
import sys
import time
import traceback
from typing import Any, Dict, List, Optional
from mcpscanner.utils.logging_config import get_logger

from mcpscanner import Config, Scanner
from mcpscanner.core.models import AnalyzerEnum
from mcpscanner.core.report_generator import (
    OutputFormat,
    ReportGenerator,
    SeverityFilter,
    results_to_json,
)
from mcpscanner.utils.logging_config import set_verbose_logging
from mcpscanner.core.auth import Auth
from mcpscanner.core.mcp_models import StdioServer

logger = get_logger(__name__)

from dotenv import load_dotenv

load_dotenv()


def _get_endpoint_from_env() -> str:
    return os.environ.get("MCP_SCANNER_ENDPOINT", "")


def _parse_custom_headers(header_list: Optional[List[str]]) -> Dict[str, str]:
    """Parse custom headers from CLI arguments.

    Args:
        header_list: List of header strings in 'Name: Value' format.

    Returns:
        Dictionary of header name to value mappings.

    Raises:
        ValueError: If a header string is not in valid format.
    """
    if not header_list:
        return {}

    headers = {}
    for header_str in header_list:
        if ':' not in header_str:
            raise ValueError(
                f"Invalid header format: '{header_str}'. Use 'Name: Value' format."
            )
        # Split on first colon only to handle values containing colons (e.g., URLs)
        name, value = header_str.split(':', 1)
        headers[name.strip()] = value.strip()
    return headers


def _create_auth_with_headers(
    bearer_token: Optional[str],
    custom_headers: Dict[str, str],
) -> Optional[Auth]:
    """Create Auth object with bearer token and/or custom headers.

    Args:
        bearer_token: Optional bearer token for authentication.
        custom_headers: Dictionary of custom headers.

    Returns:
        Auth object if any authentication is configured, None otherwise.
    """
    if not bearer_token and not custom_headers:
        return None

    if bearer_token and custom_headers:
        # Both bearer token and custom headers
        auth = Auth.bearer(bearer_token)
        auth.custom_headers = custom_headers
        return auth
    elif bearer_token:
        # Only bearer token
        return Auth.bearer(bearer_token)
    else:
        # Only custom headers
        return Auth.custom(custom_headers)


def _build_config(
    selected_analyzers: List[AnalyzerEnum], endpoint_url: Optional[str] = None
) -> Config:
    api_key = os.environ.get("MCP_SCANNER_API_KEY", "")
    llm_api_key = os.environ.get("MCP_SCANNER_LLM_API_KEY", "")
    llm_base_url = os.environ.get("MCP_SCANNER_LLM_BASE_URL")
    llm_api_version = os.environ.get("MCP_SCANNER_LLM_API_VERSION")
    llm_model = os.environ.get("MCP_SCANNER_LLM_MODEL")
    llm_timeout = os.environ.get("MCP_SCANNER_LLM_TIMEOUT")
    endpoint_url = endpoint_url or _get_endpoint_from_env()

    config_params = {
        "api_key": api_key if AnalyzerEnum.API in selected_analyzers else "",
        "endpoint_url": endpoint_url,
        "llm_provider_api_key": (
            llm_api_key if (AnalyzerEnum.LLM in selected_analyzers or AnalyzerEnum.BEHAVIORAL in selected_analyzers) else ""
        ),
        "llm_model": llm_model if (AnalyzerEnum.LLM in selected_analyzers or AnalyzerEnum.BEHAVIORAL in selected_analyzers) else "",
    }

    if llm_base_url:
        config_params["llm_base_url"] = llm_base_url
    if llm_api_version:
        config_params["llm_api_version"] = llm_api_version
    if llm_timeout:
        config_params["llm_timeout"] = float(llm_timeout)

    return Config(**config_params)


async def _run_behavioral_analyzer_on_source(source_path: str) -> List[Dict[str, Any]]:
    """Run behavioral analyzer on source code and format results.
    
    Args:
        source_path: Path to Python file or directory to analyze
        
    Returns:
        List of formatted result dictionaries
    """
    import os
    from mcpscanner.core.analyzers.behavioral import BehavioralCodeAnalyzer
    
    cfg = _build_config([AnalyzerEnum.BEHAVIORAL])
    analyzer = BehavioralCodeAnalyzer(cfg)
    
    # Analyze the source file
    findings = await analyzer.analyze(
        source_path,
        context={"file_path": source_path}
    )
    
    # Format results to match Scanner output structure
    findings_by_function = {}
    for finding in findings:
        func_name = finding.details.get("function_name", "unknown") if finding.details else "unknown"
        
        if func_name not in findings_by_function:
            findings_by_function[func_name] = []
        findings_by_function[func_name].append(finding)
    
    # Create ToolScanResult-like structure
    results = []
    for func_name, func_findings in findings_by_function.items():
        severity_order = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "SAFE": 0, "UNKNOWN": 0}
        max_severity = max((f.severity for f in func_findings), 
                         key=lambda s: severity_order.get(s, 0))
        
        source_file = func_findings[0].details.get("source_file", source_path) if func_findings[0].details else source_path
        display_name = os.path.basename(source_file) if source_file != source_path else source_path
        
        # Collect unique MCP taxonomies from all findings
        mcp_taxonomies = []
        for finding in func_findings:
            if hasattr(finding, "mcp_taxonomy") and finding.mcp_taxonomy:
                taxonomy_key = (finding.mcp_taxonomy.get("aitech"), finding.mcp_taxonomy.get("aisubtech"))
                existing_keys = [(t.get("aitech"), t.get("aisubtech")) for t in mcp_taxonomies]
                if taxonomy_key not in existing_keys:
                    mcp_taxonomies.append(finding.mcp_taxonomy)
        
        # Get threat/vulnerability classification from first finding
        threat_vuln_classification = None
        if func_findings and func_findings[0].details:
            threat_vuln_classification = func_findings[0].details.get("threat_vulnerability_classification")
        
        analyzer_finding = {
            "severity": max_severity,
            "threat_summary": func_findings[0].summary,
            "threat_names": list(set([f.threat_category for f in func_findings])),  # Deduplicate
            "total_findings": len(func_findings),
            "source_file": source_file,
            "mcp_taxonomies": mcp_taxonomies,
        }
        
        # Add threat/vulnerability classification if available
        if threat_vuln_classification:
            analyzer_finding["threat_vulnerability_classification"] = threat_vuln_classification
        
        results.append({
            "tool_name": func_name,
            "tool_description": f"MCP function from {display_name}",
            "status": "completed",
            "is_safe": False,
            "findings": {
                "behavioral_analyzer": analyzer_finding
            }
        })
    
    if not results:
        results = [{
            "tool_name": "No MCP functions found",
            "tool_description": f"No @mcp.tool() decorators found in {source_path}",
            "status": "completed",
            "is_safe": True,
            "findings": {}
        }]
    
    return results


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
        if e.__class__.__name__ in ('MCPConnectionError', 'MCPAuthenticationError', 'MCPServerNotFoundError'):
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


def display_results(results: Dict[str, Any], detailed: bool = False) -> None:
    """
    Display the scan results in a readable format.

    Args:
        results: Scan results from the MCP Scanner API
        detailed: Whether to show detailed results
    """
    print("\n=== MCP Scanner Results ===\n")

    print(f"Server URL: {results.get('server_url', 'N/A')}")

    # Display scan results
    scan_results = results.get("scan_results", [])
    print(f"Tools scanned: {len(scan_results)}")

    safe_tools = [tool for tool in scan_results if tool.get("is_safe", False)]
    unsafe_tools = [tool for tool in scan_results if not tool.get("is_safe", False)]

    print(f"Safe tools: {len(safe_tools)}")
    print(f"Unsafe tools: {len(unsafe_tools)}")

    # Display unsafe tools
    if unsafe_tools:
        print("\n=== Unsafe Tools ===\n")
        for i, tool in enumerate(unsafe_tools, 1):
            print(f"{i}. {tool.get('tool_name', 'Unknown')}")
            findings = tool.get("findings", {})

            # Count total findings across all analyzers
            total_findings = sum(
                analyzer_data.get("total_findings", 0)
                for analyzer_data in findings.values()
                if isinstance(analyzer_data, dict)
            )
            print(f"   Findings: {total_findings}")

            if detailed and findings:
                finding_num = 1
                for analyzer_name, analyzer_data in findings.items():
                    if (
                        isinstance(analyzer_data, dict)
                        and analyzer_data.get("total_findings", 0) > 0
                    ):
                        # Clean up analyzer name for display
                        clean_analyzer_name = analyzer_name.replace(
                            "_analyzer", ""
                        ).upper()

                        print(
                            f"   {finding_num}. {analyzer_data.get('threat_summary', 'No summary')}"
                        )
                        print(
                            f"      Severity: {analyzer_data.get('severity', 'Unknown')}"
                        )
                        print(f"      Analyzer: {clean_analyzer_name}")

                        # Display threat types if available
                        threat_names = analyzer_data.get("threat_names", [])
                        if threat_names:
                            threat_display = ", ".join(
                                [t.replace("_", " ").title() for t in threat_names]
                            )
                            print(f"      Threats: {threat_display}")
                        
                        # Display MCP Taxonomy if available
                        mcp_taxonomy = analyzer_data.get("mcp_taxonomy")
                        if mcp_taxonomy:
                            aitech = mcp_taxonomy.get("aitech")
                            aitech_name = mcp_taxonomy.get("aitech_name")
                            aisubtech = mcp_taxonomy.get("aisubtech")
                            aisubtech_name = mcp_taxonomy.get("aisubtech_name")
                            description = mcp_taxonomy.get("description")
                            
                            if aitech:
                                print(f"      Technique: {aitech} - {aitech_name}")
                            if aisubtech:
                                print(f"      Sub-Technique: {aisubtech} - {aisubtech_name}")
                            if description:
                                print(f"      Description: {description}")

                        print()
                        finding_num += 1
            print()


def display_prompt_results_table(results: List[Dict[str, Any]], server_url: str) -> None:
    """Display prompt scan results in table format."""
    try:
        from tabulate import tabulate
    except ImportError:
        print("⚠️  tabulate package not installed. Install with: pip install tabulate")
        print("Falling back to summary format...\n")
        display_prompt_results(results, server_url, detailed=False)
        return

    print("\n=== MCP Prompt Scanner Results (Table) ===\n")
    print(f"Server URL: {server_url}\n")

    # Prepare table data
    table_data = []
    for result in results:
        status_icon = "✅" if result.get("is_safe", False) else "⚠️"
        prompt_name = result.get("prompt_name", "Unknown")
        desc = result.get("prompt_description", "")
        desc_short = desc[:40] + "..." if len(desc) > 40 else desc
        findings_count = len(result.get("findings", []))
        status = result.get("status", "unknown")

        table_data.append([
            status_icon,
            prompt_name,
            desc_short,
            findings_count,
            status
        ])

    headers = ["Status", "Prompt Name", "Description", "Findings", "Scan Status"]
    print(tabulate(table_data, headers=headers, tablefmt="grid"))

    # Summary
    safe = sum(1 for r in results if r.get("is_safe", False))
    unsafe = sum(1 for r in results if not r.get("is_safe", False))
    print(f"\n📊 Summary: {len(results)} total | {safe} safe | {unsafe} unsafe")


def display_resource_results_table(results: List[Dict[str, Any]], server_url: str) -> None:
    """Display resource scan results in table format."""
    try:
        from tabulate import tabulate
    except ImportError:
        print("⚠️  tabulate package not installed. Install with: pip install tabulate")
        print("Falling back to summary format...\n")
        display_resource_results(results, server_url, detailed=False)
        return

    print("\n=== MCP Resource Scanner Results (Table) ===\n")
    print(f"Server URL: {server_url}\n")

    # Prepare table data
    table_data = []
    for result in results:
        status = result.get("status", "unknown")

        if status == "completed":
            status_icon = "✅" if result.get("is_safe", False) else "⚠️"
        elif status == "skipped":
            status_icon = "⏭️"
        else:
            status_icon = "❌"

        resource_name = result.get("resource_name", "Unknown")
        uri = result.get("resource_uri", "N/A")
        uri_short = uri[:40] + "..." if len(uri) > 40 else uri
        mime_type = result.get("resource_mime_type", "unknown")
        findings_count = len(result.get("findings", [])) if status == "completed" else "-"

        table_data.append([
            status_icon,
            resource_name,
            uri_short,
            mime_type,
            findings_count,
            status
        ])

    headers = ["Status", "Resource Name", "URI", "MIME Type", "Findings", "Scan Status"]
    print(tabulate(table_data, headers=headers, tablefmt="grid"))

    # Summary
    completed = [r for r in results if r.get("status") == "completed"]
    skipped = [r for r in results if r.get("status") == "skipped"]
    failed = [r for r in results if r.get("status") == "failed"]
    safe = sum(1 for r in completed if r.get("is_safe", False))
    unsafe = sum(1 for r in completed if not r.get("is_safe", False))

    print(f"\n📊 Summary: {len(results)} total | {len(completed)} scanned | {len(skipped)} skipped | {len(failed)} failed")
    if completed:
        print(f"   Security: {safe} safe | {unsafe} unsafe")


def display_prompt_results(results: List[Dict[str, Any]], server_url: str, detailed: bool = False) -> None:
    """
    Display prompt scan results in a readable format.

    Args:
        results: List of prompt scan results
        server_url: The server URL that was scanned
        detailed: Whether to show detailed results
    """
    print("\n=== MCP Prompt Scanner Results ===\n")
    print(f"Server URL: {server_url}")
    print(f"Prompts scanned: {len(results)}")

    safe_prompts = [p for p in results if p.get("is_safe", False)]
    unsafe_prompts = [p for p in results if not p.get("is_safe", False)]

    print(f"Safe prompts: {len(safe_prompts)}")
    print(f"Unsafe prompts: {len(unsafe_prompts)}")

    # Display unsafe prompts
    if unsafe_prompts:
        print("\n=== Unsafe Prompts ===\n")
        for i, prompt in enumerate(unsafe_prompts, 1):
            print(f"{i}. {prompt.get('prompt_name', 'Unknown')}")
            if prompt.get('prompt_description'):
                desc = prompt['prompt_description']
                print(f"   Description: {desc[:80]}{'...' if len(desc) > 80 else ''}")

            findings = prompt.get("findings", [])
            print(f"   Findings: {len(findings)}")

            if detailed and findings:
                for j, finding in enumerate(findings, 1):
                    print(f"   {j}. {finding.get('summary', 'No summary')}")
                    print(f"      Severity: {finding.get('severity', 'Unknown')}")
                    print(f"      Analyzer: {finding.get('analyzer', 'Unknown')}")

                    details = finding.get("details", {})
                    if details.get("primary_threats"):
                        threats = ", ".join([t.replace("_", " ").title() for t in details["primary_threats"]])
                        print(f"      Threats: {threats}")
                    
                    mcp_taxonomy = finding.get("mcp_taxonomy")
                    if mcp_taxonomy:
                        aitech = mcp_taxonomy.get("aitech")
                        aitech_name = mcp_taxonomy.get("aitech_name")
                        aisubtech = mcp_taxonomy.get("aisubtech")
                        aisubtech_name = mcp_taxonomy.get("aisubtech_name")
                        description = mcp_taxonomy.get("description")
                        
                        if aitech:
                            print(f"      Technique: {aitech} - {aitech_name}")
                        if aisubtech:
                            print(f"      Sub-Technique: {aisubtech} - {aisubtech_name}")
                        if description:
                            print(f"      Description: {description}")
                    print()
            print()

    # Display safe prompts if detailed
    if detailed and safe_prompts:
        print("\n=== Safe Prompts ===\n")
        for i, prompt in enumerate(safe_prompts, 1):
            print(f"{i}. {prompt.get('prompt_name', 'Unknown')}")
            if prompt.get('prompt_description'):
                desc = prompt['prompt_description']
                print(f"   Description: {desc[:80]}{'...' if len(desc) > 80 else ''}")
            print()


def display_resource_results(results: List[Dict[str, Any]], server_url: str, detailed: bool = False) -> None:
    """
    Display resource scan results in a readable format.

    Args:
        results: List of resource scan results
        server_url: The server URL that was scanned
        detailed: Whether to show detailed results
    """
    print("\n=== MCP Resource Scanner Results ===\n")
    print(f"Server URL: {server_url}")
    print(f"Resources found: {len(results)}")

    completed = [r for r in results if r.get("status") == "completed"]
    skipped = [r for r in results if r.get("status") == "skipped"]
    failed = [r for r in results if r.get("status") == "failed"]

    print(f"Scanned: {len(completed)}")
    print(f"Skipped: {len(skipped)}")
    print(f"Failed: {len(failed)}")

    if completed:
        safe_resources = [r for r in completed if r.get("is_safe", False)]
        unsafe_resources = [r for r in completed if not r.get("is_safe", False)]

        print(f"Safe resources: {len(safe_resources)}")
        print(f"Unsafe resources: {len(unsafe_resources)}")

        # Display unsafe resources
        if unsafe_resources:
            print("\n=== Unsafe Resources ===\n")
            for i, resource in enumerate(unsafe_resources, 1):
                print(f"{i}. {resource.get('resource_name', 'Unknown')}")
                print(f"   URI: {resource.get('resource_uri', 'N/A')}")
                print(f"   MIME Type: {resource.get('resource_mime_type', 'unknown')}")

                findings = resource.get("findings", [])
                print(f"   Findings: {len(findings)}")

                if detailed and findings:
                    for j, finding in enumerate(findings, 1):
                        print(f"   {j}. {finding.get('summary', 'No summary')}")
                        print(f"      Severity: {finding.get('severity', 'Unknown')}")
                        print(f"      Analyzer: {finding.get('analyzer', 'Unknown')}")

                        details = finding.get("details", {})
                        if details.get("primary_threats"):
                            threats = ", ".join([t.replace("_", " ").title() for t in details["primary_threats"]])
                            print(f"      Threats: {threats}")
                        
                        # Display MCP Taxonomy if available
                        mcp_taxonomy = finding.get("mcp_taxonomy")
                        if mcp_taxonomy:
                            aitech = mcp_taxonomy.get("aitech")
                            aitech_name = mcp_taxonomy.get("aitech_name")
                            aisubtech = mcp_taxonomy.get("aisubtech")
                            aisubtech_name = mcp_taxonomy.get("aisubtech_name")
                            description = mcp_taxonomy.get("description")
                            
                            if aitech:
                                print(f"      Technique: {aitech} - {aitech_name}")
                            if aisubtech:
                                print(f"      Sub-Technique: {aisubtech} - {aisubtech_name}")
                            if description:
                                print(f"      Description: {description}")
                        print()
                print()

        # Display safe resources if detailed
        if detailed and safe_resources:
            print("\n=== Safe Resources ===\n")
            for i, resource in enumerate(safe_resources, 1):
                print(f"{i}. {resource.get('resource_name', 'Unknown')}")
                print(f"   URI: {resource.get('resource_uri', 'N/A')}")
                print(f"   MIME Type: {resource.get('resource_mime_type', 'unknown')}")
                print()

    # Display skipped resources if any
    if skipped and detailed:
        print("\n=== Skipped Resources ===\n")
        for i, resource in enumerate(skipped, 1):
            print(f"{i}. {resource.get('resource_name', 'Unknown')}")
            print(f"   URI: {resource.get('resource_uri', 'N/A')}")
            print(f"   MIME Type: {resource.get('resource_mime_type', 'unknown')}")
            print()


def display_instructions_results_table(results: List[Dict[str, Any]], server_url: str) -> None:
    """Display instructions scan results in table format."""
    try:
        from tabulate import tabulate
    except ImportError:
        print("⚠️  tabulate package not installed. Install with: pip install tabulate")
        print("Falling back to summary format...\n")
        display_instructions_results(results, server_url, detailed=False)
        return

    print("\n=== MCP Instructions Scanner Results (Table) ===\n")
    print(f"Server URL: {server_url}\n")

    # Prepare table data
    table_data = []
    for result in results:
        status = result.get("status", "unknown")
        status_icon = "✅" if result.get("is_safe", False) else "⚠️"
        server_name = result.get("server_name", "Unknown")
        protocol_version = result.get("protocol_version", "N/A")
        findings_count = len(result.get("findings", []))
        instructions_preview = result.get("instructions", "")[:50] + "..." if len(result.get("instructions", "")) > 50 else result.get("instructions", "")

        table_data.append([
            status_icon,
            server_name,
            protocol_version,
            instructions_preview,
            findings_count,
            status
        ])

    headers = ["Status", "Server Name", "Protocol", "Instructions Preview", "Findings", "Scan Status"]
    print(tabulate(table_data, headers=headers, tablefmt="grid"))

    # Summary
    safe = sum(1 for r in results if r.get("is_safe", False))
    unsafe = sum(1 for r in results if not r.get("is_safe", False))
    print(f"\n📊 Summary: {len(results)} scanned | {safe} safe | {unsafe} unsafe")


def display_instructions_results(results: List[Dict[str, Any]], server_url: str, detailed: bool = False) -> None:
    """Display instructions scan results in a readable format.

    Args:
        results: List of instructions scan results
        server_url: The server URL that was scanned
        detailed: Whether to show detailed results
    """
    print("\n=== MCP Instructions Scanner Results ===\n")
    print(f"Server URL: {server_url}")
    print(f"Instructions scanned: {len(results)}")

    safe_instructions = [i for i in results if i.get("is_safe", False)]
    unsafe_instructions = [i for i in results if not i.get("is_safe", False)]

    print(f"Safe: {len(safe_instructions)}")
    print(f"Unsafe: {len(unsafe_instructions)}")

    # Display unsafe instructions
    if unsafe_instructions:
        print("\n=== Unsafe Instructions ===\n")
        for i, instr in enumerate(unsafe_instructions, 1):
            print(f"{i}. Server: {instr.get('server_name', 'Unknown')}")
            print(f"   Protocol: {instr.get('protocol_version', 'N/A')}")
            instructions_text = instr.get('instructions', '')
            if instructions_text:
                preview = instructions_text[:100] + "..." if len(instructions_text) > 100 else instructions_text
                print(f"   Instructions: {preview}")

            findings = instr.get("findings", [])
            print(f"   Findings: {len(findings)}")

            if detailed and findings:
                for j, finding in enumerate(findings, 1):
                    print(f"   {j}. {finding.get('summary', 'No summary')}")
                    print(f"      Severity: {finding.get('severity', 'Unknown')}")
                    print(f"      Analyzer: {finding.get('analyzer', 'Unknown')}")

                    details = finding.get("details", {})
                    if details.get("primary_threats"):
                        threats = ", ".join([t.replace("_", " ").title() for t in details["primary_threats"]])
                        print(f"      Threats: {threats}")
                    
                    mcp_taxonomy = finding.get("mcp_taxonomy")
                    if mcp_taxonomy:
                        aitech = mcp_taxonomy.get("aitech")
                        aitech_name = mcp_taxonomy.get("aitech_name")
                        aisubtech = mcp_taxonomy.get("aisubtech")
                        aisubtech_name = mcp_taxonomy.get("aisubtech_name")
                        description = mcp_taxonomy.get("description")
                        
                        if aitech:
                            print(f"      Technique: {aitech} - {aitech_name}")
                        if aisubtech:
                            print(f"      Sub-Technique: {aisubtech} - {aisubtech_name}")
                        if description:
                            print(f"      Description: {description}")
                    print()
            print()

    # Display safe instructions if detailed
    if detailed and safe_instructions:
        print("\n=== Safe Instructions ===\n")
        for i, instr in enumerate(safe_instructions, 1):
            print(f"{i}. Server: {instr.get('server_name', 'Unknown')}")
            print(f"   Protocol: {instr.get('protocol_version', 'N/A')}")
            instructions_text = instr.get('instructions', '')
            if instructions_text:
                preview = instructions_text[:100] + "..." if len(instructions_text) > 100 else instructions_text
                print(f"   Instructions: {preview}")
            print()


async def main():
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(
        description="MCP Security Scanner - Comprehensive security analysis for MCP servers",
        epilog="""Examples:
  %(prog)s                                                    # Basic security scan with summary (all analyzers)
  %(prog)s --api-key YOUR_API_KEY --endpoint-url <your-endpoint> # Scan with an endpoint
  %(prog)s --format detailed --api-key YOUR_API_KEY         # Detailed security findings report with API
  %(prog)s --format by_analyzer --llm-api-key YOUR_LLM_KEY  # Group findings by analysis engine with LLM
  %(prog)s --format table --analyzers yara                  # YARA-only scanning with table format
  %(prog)s --analyzers api,yara --severity-filter high      # API and YARA analysis, high severity only
  %(prog)s --analyzer-filter llm_analyzer --stats           # Show only LLM analysis with statistics
  %(prog)s --tool-filter "database" --output results.json  # Filter and save results to file
  %(prog)s --analyzers llm --raw                            # LLM-only scan with raw JSON output
  %(prog)s --analyzers api,llm --hide-safe                  # API and LLM scan, hide safe results
  %(prog)s --scan-known-configs --expand-vars auto          # Scan configs with OS-appropriate expansion
  %(prog)s --scan-known-configs --expand-vars linux/mac         # Expand $VAR and ${VAR} only (POSIX)
  %(prog)s --scan-known-configs --expand-vars windows       # Expand %%VAR%% only (Windows style)
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Subcommands for scan modes (remote, stdio, config, known-configs, prompts, resources, instructions)
    subparsers = parser.add_subparsers(dest="cmd")

    p_remote = subparsers.add_parser(
        "remote", help="Scan a remote MCP server (SSE or streamable HTTP)"
    )
    p_remote.add_argument(
        "--server-url",
        required=True,
        help="URL of the MCP server to scan",
    )
    p_remote.add_argument(
        "--bearer-token",
        help="Bearer token to use for remote MCP server authentication (Authorization: Bearer <token>)",
    )
    p_remote.add_argument(
        "--header",
        action="append",
        dest="custom_headers",
        metavar="NAME:VALUE",
        help="Custom HTTP header in format 'Name: Value'. Can be specified multiple times.",
    )

    # Prompts subcommand
    p_prompts = subparsers.add_parser(
        "prompts", help="Scan prompts on an MCP server"
    )
    p_prompts.add_argument(
        "--server-url",
        required=True,
        help="URL of the MCP server to scan",
    )
    p_prompts.add_argument(
        "--bearer-token",
        help="Bearer token for authentication",
    )
    p_prompts.add_argument(
        "--header",
        action="append",
        dest="custom_headers",
        metavar="NAME:VALUE",
        help="Custom HTTP header in format 'Name: Value'. Can be specified multiple times.",
    )
    p_prompts.add_argument(
        "--prompt-name",
        help="Scan a specific prompt by name (if not provided, scans all prompts)",
    )

    # Resources subcommand
    p_resources = subparsers.add_parser(
        "resources", help="Scan resources on an MCP server"
    )
    p_resources.add_argument(
        "--server-url",
        required=True,
        help="URL of the MCP server to scan",
    )
    p_resources.add_argument(
        "--bearer-token",
        help="Bearer token for authentication",
    )
    p_resources.add_argument(
        "--header",
        action="append",
        dest="custom_headers",
        metavar="NAME:VALUE",
        help="Custom HTTP header in format 'Name: Value'. Can be specified multiple times.",
    )
    p_resources.add_argument(
        "--resource-uri",
        help="Scan a specific resource by URI (if not provided, scans all resources)",
    )
    p_resources.add_argument(
        "--mime-types",
        default="text/plain,text/html",
        help="Comma-separated list of allowed MIME types (default: %(default)s)",
    )

    # Instructions subcommand
    p_instructions = subparsers.add_parser(
        "instructions", help="Scan server instructions on an MCP server"
    )
    p_instructions.add_argument(
        "--server-url",
        required=True,
        help="URL of the MCP server to scan",
    )
    p_instructions.add_argument(
        "--bearer-token",
        help="Bearer token for authentication",
    )

    # Behavioral subcommand - scan local source code
    p_behavioral = subparsers.add_parser(
        "behavioral", help="Scan MCP server source code for docstring/behavior mismatches"
    )
    p_behavioral.add_argument(
        "source_path",
        help="Path to MCP server source code file or directory",
    )
    p_behavioral.add_argument(
        "--output", "-o",
        help="Save scan results to a file",
    )
    p_behavioral.add_argument(
        "--verbose", "-v", action="store_true", help="Print verbose output"
    )
    p_behavioral.add_argument(
        "--raw", "-r", action="store_true", help="Print raw JSON output"
    )
    p_behavioral.add_argument(
        "--detailed", "-d", action="store_true", help="Show detailed results"
    )
    p_behavioral.add_argument(
        "--format",
        choices=["raw", "summary", "detailed", "by_tool", "by_analyzer", "by_severity", "table"],
        default="summary",
        help="Output format (default: %(default)s)",
    )


    # Stdio subcommand
    p_stdio = subparsers.add_parser(
        "stdio", help="Scan an MCP server via stdio (local command execution)"
    )
    p_stdio.add_argument(
        "--stdio-command",
        required=True,
        help="Command to run the stdio-based MCP server (e.g., 'uvx')",
    )
    p_stdio.add_argument(
        "--stdio-args",
        nargs="*",
        default=[],
        help="Arguments passed to the stdio command (space-separated)",
    )
    p_stdio.add_argument(
        "--stdio-env",
        action="append",
        default=[],
        help="Environment variables for the stdio server in KEY=VALUE form; can be repeated",
    )
    p_stdio.add_argument(
        "--stdio-tool",
        help="If provided, only scan this specific tool name on the stdio server",
    )

    # Config subcommand
    p_config = subparsers.add_parser(
        "config", help="Scan all servers defined in a specific MCP config file"
    )
    p_config.add_argument(
        "--config-path",
        required=True,
        help="Path to MCP config file (e.g., ~/.codeium/windsurf/mcp_config.json)",
    )
    p_config.add_argument(
        "--bearer-token",
        help="Bearer token for authentication",
    )

    # Known-configs subcommand
    p_known_configs = subparsers.add_parser(
        "known-configs", help="Scan all well-known MCP client config files on this machine"
    )
    p_known_configs.add_argument(
        "--bearer-token",
        help="Bearer token for authentication",
    )

    # API key and endpoint configuration
    parser.add_argument(
        "--api-key",
        help="Cisco AI Defense API key (overrides MCP_SCANNER_API_KEY environment variable)",
    )
    parser.add_argument(
        "--endpoint-url",
        help="Cisco AI Defense endpoint URL (overrides MCP_SCANNER_ENDPOINT environment variable)",
    )
    parser.add_argument(
        "--llm-api-key",
        help="LLM provider API key for LLM analysis (overrides environment variable)",
    )
    parser.add_argument(
        "--llm-timeout",
        type=int,
        help="Timeout in seconds for LLM API calls (overrides MCP_SCANNER_LLM_TIMEOUT environment variable)",
    )

    parser.add_argument(
        "--analyzers",
        default="api,yara,llm",
        help="Comma-separated list of analyzers to run. Options: api, yara, llm, behavioral (default: %(default)s)",
    )

    parser.add_argument("--output", "-o", help="Save scan results to a file")
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Print verbose output"
    )
    parser.add_argument(
        "--detailed", "-d", action="store_true", help="Show detailed results"
    )
    parser.add_argument(
        "--raw", "-r", action="store_true", help="Print raw JSON output to terminal"
    )
    parser.add_argument(
        "--expand-vars",
        choices=["auto", "linux", "mac", "windows", "off"],
        default="off",
        help=(
            "Control env var expansion for stdio command/args. "
            "off: no env expansion (only ~). "
            "linux/mac: expand $VAR and ${VAR} (POSIX). "
            "windows: expand %VAR% (Windows style only). "
            "auto: linux/mac on POSIX, windows on Windows."
        ),
    )

    parser.add_argument(
        "--server-url",
        default="https://mcp.deepwiki.com/mcp",
        help="URL of the MCP server to scan (default: %(default)s)",
    )
    parser.add_argument(
        "--scan-known-configs",
        action="store_true",
        help="Scan all well-known MCP client config files on this machine (windsurf, cursor, claude, vscode)",
    )
    parser.add_argument(
        "--config-path",
        help="Scan all servers defined in a specific MCP config file (e.g., ~/.codeium/windsurf/mcp_config.json)",
    )
    parser.add_argument(
        "--stdio-command",
        help="Run a stdio-based MCP server using the given command (e.g., 'uvx')",
    )
    parser.add_argument(
        "--stdio-args",
        nargs="*",
        default=[],
        help="Arguments passed to the stdio command (space-separated)",
    )
    parser.add_argument(
        "--stdio-arg",
        action="append",
        help="[Deprecated] Repeatable single arg; use --stdio-args instead",
    )
    parser.add_argument(
        "--stdio-env",
        action="append",
        default=[],
        help="Environment variables for the stdio server in KEY=VALUE form; can be repeated",
    )
    parser.add_argument(
        "--stdio-tool",
        help="If provided, only scan this specific tool name on the stdio server",
    )

    # Back-compat bearer
    parser.add_argument(
        "--bearer-token",
        help="Bearer token to use for remote MCP server authentication (Authorization: Bearer <token>)",
    )

    parser.add_argument(
        "--format",
        choices=[
            "raw",
            "summary",
            "detailed",
            "by_tool",
            "by_analyzer",
            "by_severity",
            "table",
        ],
        default="summary",
        help="Output format (default: %(default)s)",
    )
    parser.add_argument(
        "--tool-filter", help="Filter results by tool name (partial match)"
    )
    parser.add_argument(
        "--analyzer-filter",
        choices=["api_analyzer", "yara_analyzer", "llm_analyzer", "behavioral_analyzer"],
        help="Filter results by specific analyzer",
    )
    parser.add_argument(
        "--severity-filter",
        choices=["all", "high", "unknown", "medium", "low", "safe"],
        default="all",
        help="Filter results by severity level (default: %(default)s)",
    )
    parser.add_argument(
        "--hide-safe", action="store_true", help="Hide safe tools from output"
    )
    parser.add_argument(
        "--stats", action="store_true", help="Show statistics about scan results"
    )
    parser.add_argument(
        "--rules-path",
        help="Path to directory containing custom YARA rules",
    )
    parser.add_argument(
        "--source-path",
        help="Path to MCP server source code file or directory (required for behavioral analyzer)",
    )

    args = parser.parse_args()

    # Parse analyzers argument into AnalyzerEnum list
    analyzer_names = [a.strip().lower() for a in args.analyzers.split(",")]
    valid_analyzer_names = {e.value for e in AnalyzerEnum}

    # Validate analyzer names
    invalid_analyzers = set(analyzer_names) - valid_analyzer_names
    if invalid_analyzers:
        parser.error(
            f"Invalid analyzers: {', '.join(invalid_analyzers)}. Valid options: {', '.join(valid_analyzer_names)}"
        )

    # Convert to AnalyzerEnum list
    selected_analyzers = [AnalyzerEnum(name) for name in analyzer_names]

    # Validate behavioral analyzer requirements
    if AnalyzerEnum.BEHAVIORAL in selected_analyzers:
        if not args.source_path and not (hasattr(args, 'cmd') and args.cmd == 'behavioral'):
            parser.error(
                "Behavioral analyzer requires --source-path argument. "
                "Usage: mcp-scanner --source-path FILE --analyzers behavioral"
            )

    if args.verbose:
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            stream=sys.stdout,
        )
        logging.getLogger("mcpscanner").setLevel(logging.DEBUG)
        set_verbose_logging(True)
        logger.info("Verbose output enabled - detailed analyzer logs will be shown")
    else:
        logging.basicConfig(
            level=logging.WARNING,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            stream=sys.stdout,
        )
        logging.getLogger("mcpscanner").setLevel(logging.WARNING)
        set_verbose_logging(False)

    if args.api_key:
        os.environ["MCP_SCANNER_API_KEY"] = args.api_key
    if args.endpoint_url:
        os.environ["MCP_SCANNER_ENDPOINT"] = args.endpoint_url
    if args.llm_api_key:
        os.environ["MCP_SCANNER_LLM_API_KEY"] = args.llm_api_key
    if args.llm_timeout:
        os.environ["MCP_SCANNER_LLM_TIMEOUT"] = str(args.llm_timeout)

    try:
        if args.cmd == "remote":
            cfg = _build_config(selected_analyzers)
            scanner = Scanner(cfg, rules_dir=args.rules_path)
            # Parse custom headers and create auth
            custom_headers = _parse_custom_headers(getattr(args, 'custom_headers', None))
            auth = _create_auth_with_headers(args.bearer_token, custom_headers)
            results_raw = await scanner.scan_remote_server_tools(
                args.server_url, auth=auth, analyzers=selected_analyzers
            )
            results = await results_to_json(results_raw)

        elif args.cmd == "stdio":
            cfg = _build_config(selected_analyzers)
            scanner = Scanner(cfg, rules_dir=args.rules_path)
            env_dict = {}
            for item in args.stdio_env or []:
                if "=" in item:
                    k, v = item.split("=", 1)
                    env_dict[k] = v
            stdio_args = list(args.stdio_args or [])
            if getattr(args, "stdio_arg", None):
                print("[warning] --stdio-arg is deprecated; use --stdio-args")
                stdio_args.extend(args.stdio_arg)
            stdio = StdioServer(
                command=args.stdio_command,
                args=stdio_args,
                env=env_dict or None,
                expand_vars=args.expand_vars,
            )
            if args.stdio_tool:
                scan_result = await scanner.scan_stdio_server_tool(
                    stdio, args.stdio_tool, analyzers=selected_analyzers
                )
                results = await results_to_json([scan_result])
            else:
                scan_results = await scanner.scan_stdio_server_tools(
                    stdio, analyzers=selected_analyzers
                )
                results = await results_to_json(scan_results)

        elif args.cmd == "config":
            cfg = _build_config(selected_analyzers)
            scanner = Scanner(cfg, rules_dir=args.rules_path)
            auth = Auth.bearer(args.bearer_token) if args.bearer_token else None
            scan_results = await scanner.scan_mcp_config_file(
                args.config_path,
                analyzers=selected_analyzers,
                auth=auth,
                expand_vars_default=args.expand_vars,
            )
            results = await results_to_json(scan_results)

        elif args.cmd == "known-configs":
            cfg = _build_config(selected_analyzers)
            scanner = Scanner(cfg, rules_dir=args.rules_path)
            auth = Auth.bearer(args.bearer_token) if args.bearer_token else None
            results_by_cfg = await scanner.scan_well_known_mcp_configs(
                analyzers=selected_analyzers,
                auth=auth,
                expand_vars_default=args.expand_vars,
            )
            if args.raw:
                output = {}
                for cfg_path, scan_results in results_by_cfg.items():
                    output[cfg_path] = await results_to_json(scan_results)
                print(json.dumps(output, indent=2))
                return
            flattened = []
            for scan_results in results_by_cfg.values():
                flattened.extend(scan_results)
            results = await results_to_json(flattened)

        elif args.cmd == "prompts":
            cfg = _build_config(selected_analyzers)
            scanner = Scanner(cfg, rules_dir=args.rules_path)
            # Parse custom headers and create auth
            custom_headers = _parse_custom_headers(getattr(args, 'custom_headers', None))
            auth = _create_auth_with_headers(args.bearer_token, custom_headers)

            if args.prompt_name:
                # Scan specific prompt
                result = await scanner.scan_remote_server_prompt(
                    server_url=args.server_url,
                    prompt_name=args.prompt_name,
                    auth=auth,
                    analyzers=selected_analyzers,
                )
                # Convert PromptScanResult to dict format
                results = [{
                    "prompt_name": result.prompt_name,
                    "prompt_description": result.prompt_description,
                    "status": result.status,
                    "is_safe": result.is_safe,
                    "findings": [
                        {
                            "severity": f.severity,
                            "summary": f.summary,
                            "analyzer": f.analyzer,
                            "details": f.details,
                            "mcp_taxonomy": f.mcp_taxonomy if hasattr(f, "mcp_taxonomy") else None,
                        }
                        for f in result.findings
                    ],
                }]
            else:
                # Scan all prompts
                prompt_results = await scanner.scan_remote_server_prompts(
                    server_url=args.server_url,
                    auth=auth,
                    analyzers=selected_analyzers,
                )
                results = [
                    {
                        "prompt_name": r.prompt_name,
                        "prompt_description": r.prompt_description,
                        "status": r.status,
                        "is_safe": r.is_safe,
                        "findings": [
                            {
                                "severity": f.severity,
                                "summary": f.summary,
                                "analyzer": f.analyzer,
                                "details": f.details,
                                "mcp_taxonomy": f.mcp_taxonomy if hasattr(f, "mcp_taxonomy") else None,
                            }
                            for f in r.findings
                        ],
                    }
                    for r in prompt_results
                ]

        elif args.cmd == "resources":
            cfg = _build_config(selected_analyzers)
            scanner = Scanner(cfg, rules_dir=args.rules_path)
            # Parse custom headers and create auth
            custom_headers = _parse_custom_headers(getattr(args, 'custom_headers', None))
            auth = _create_auth_with_headers(args.bearer_token, custom_headers)

            # Parse MIME types
            allowed_mime_types = [m.strip() for m in args.mime_types.split(",")]

            if args.resource_uri:
                # Scan specific resource
                result = await scanner.scan_remote_server_resource(
                    server_url=args.server_url,
                    resource_uri=args.resource_uri,
                    auth=auth,
                    analyzers=selected_analyzers,
                    allowed_mime_types=allowed_mime_types,
                )
                # Convert ResourceScanResult to dict format
                results = [{
                    "resource_uri": str(result.resource_uri),
                    "resource_name": result.resource_name,
                    "resource_mime_type": result.resource_mime_type,
                    "status": result.status,
                    "is_safe": result.is_safe if result.status == "completed" else None,
                    "findings": [
                        {
                            "severity": f.severity,
                            "summary": f.summary,
                            "analyzer": f.analyzer,
                            "details": f.details,
                            "mcp_taxonomy": f.mcp_taxonomy if hasattr(f, "mcp_taxonomy") else None,
                        }
                        for f in result.findings
                    ],
                }]
            else:
                # Scan all resources
                resource_results = await scanner.scan_remote_server_resources(
                    server_url=args.server_url,
                    auth=auth,
                    analyzers=selected_analyzers,
                    allowed_mime_types=allowed_mime_types,
                )
                results = [
                    {
                        "resource_uri": str(r.resource_uri),
                        "resource_name": r.resource_name,
                        "resource_mime_type": r.resource_mime_type,
                        "status": r.status,
                        "is_safe": r.is_safe if r.status == "completed" else None,
                        "findings": [
                            {
                                "severity": f.severity,
                                "summary": f.summary,
                                "analyzer": f.analyzer,
                                "details": f.details,
                                "mcp_taxonomy": f.mcp_taxonomy if hasattr(f, "mcp_taxonomy") else None,
                            }
                            for f in r.findings
                        ],
                    }
                    for r in resource_results
                ]

        elif args.cmd == "instructions":
            cfg = _build_config(selected_analyzers)
            scanner = Scanner(cfg, rules_dir=args.rules_path)
            auth = Auth.bearer(args.bearer_token) if args.bearer_token else None

            # Scan server instructions
            result = await scanner.scan_remote_server_instructions(
                server_url=args.server_url,
                auth=auth,
                analyzers=selected_analyzers,
            )
            # Convert InstructionsScanResult to dict format
            results = [{
                "instructions": result.instructions,
                "server_name": result.server_name,
                "protocol_version": result.protocol_version,
                "status": result.status,
                "is_safe": result.is_safe,
                "findings": [
                    {
                        "severity": f.severity,
                        "summary": f.summary,
                        "analyzer": f.analyzer,
                        "details": f.details,
                        "mcp_taxonomy": f.mcp_taxonomy if hasattr(f, "mcp_taxonomy") else None,
                    }
                    for f in result.findings
                ],
            }]

        elif args.cmd == "behavioral":
            # Behavioral analyzer - scan local source code  
            # This follows the same pattern as other analyzers but operates on source files
            cfg = _build_config([AnalyzerEnum.BEHAVIORAL])
            
            from mcpscanner.core.analyzers.behavioral import BehavioralCodeAnalyzer
            analyzer = BehavioralCodeAnalyzer(cfg)
            
            source_path = args.source_path
            
            # Analyze the source file
            findings = await analyzer.analyze(
                source_path,
                context={"file_path": source_path}
            )
            
            # Format results to match Scanner output structure
            # Group findings by function to create tool-like results
            findings_by_function = {}
            for finding in findings:
                # Extract function name from details (not summary!)
                func_name = finding.details.get("function_name", "unknown") if finding.details else "unknown"
                
                if func_name not in findings_by_function:
                    findings_by_function[func_name] = []
                findings_by_function[func_name].append(finding)
            
            # Create ToolScanResult-like structure for each function
            results = []
            for func_name, func_findings in findings_by_function.items():
                # Get highest severity
                severity_order = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "SAFE": 0, "UNKNOWN": 0}
                max_severity = max((f.severity for f in func_findings), 
                                 key=lambda s: severity_order.get(s, 0))
                
                # Get source file from findings (for directory scans)
                source_file = func_findings[0].details.get("source_file", source_path) if func_findings[0].details else source_path
                import os
                display_name = os.path.basename(source_file) if source_file != source_path else source_path
                
                # Collect all taxonomies from findings
                mcp_taxonomies = []
                for finding in func_findings:
                    if hasattr(finding, "mcp_taxonomy") and finding.mcp_taxonomy:
                        if finding.mcp_taxonomy not in mcp_taxonomies:
                            mcp_taxonomies.append(finding.mcp_taxonomy)
                
                # Get threat/vulnerability classification from first finding
                threat_vuln_classification = None
                if func_findings and func_findings[0].details:
                    threat_vuln_classification = func_findings[0].details.get("threat_vulnerability_classification")
                
                # Determine if safe based on severity
                is_safe = max_severity in ["SAFE", "LOW"]
                
                analyzer_finding = {
                    "severity": max_severity,
                    "threat_summary": func_findings[0].summary,
                    "threat_names": list(set([f.threat_category for f in func_findings])),  # Deduplicate
                    "total_findings": len(func_findings),
                    "source_file": source_file,  # Include source file in output
                    "mcp_taxonomies": mcp_taxonomies,  # All unique taxonomies
                }
                
                # Add threat/vulnerability classification if available
                if threat_vuln_classification:
                    analyzer_finding["threat_vulnerability_classification"] = threat_vuln_classification
                
                results.append({
                    "tool_name": func_name,  # This should match the name from decorator params or function name
                    "tool_description": f"MCP function from {display_name}",
                    "status": "completed",
                    "is_safe": is_safe,
                    "findings": {
                        "behavioral_analyzer": analyzer_finding
                    }
                })
            
            # If no findings, all functions are safe
            if not results:
                results.append({
                    "tool_name": source_path,
                    "tool_description": "MCP server source code",
                    "status": "completed",
                    "is_safe": True,
                    "findings": {}
                })
            
            # Automatically filter out VULNERABILITY findings - only show THREATS
            filtered_results = []
            for result in results:
                # Check if result has behavioral_analyzer findings with classification
                if "findings" in result and "behavioral_analyzer" in result["findings"]:
                    analyzer_data = result["findings"]["behavioral_analyzer"]
                    classification = analyzer_data.get("threat_vulnerability_classification", "").upper()
                    
                    # Only include THREAT findings, exclude VULNERABILITY
                    if classification == "THREAT":
                        filtered_results.append(result)
                # Keep results without findings (safe results)
                elif not result.get("findings"):
                    filtered_results.append(result)
            
            results = filtered_results
            
            # Save output if requested
            if args.output:
                with open(args.output, "w", encoding="utf-8") as f:
                    json.dump(results, f, indent=2)
                if args.verbose:
                    print(f"Results saved to {args.output}")

        # Backward compatibility path (no subcommand used)
        elif args.stdio_command:
            cfg = _build_config(selected_analyzers)
            scanner = Scanner(cfg, rules_dir=args.rules_path)
            env_dict = {}
            for item in args.stdio_env or []:
                if "=" in item:
                    k, v = item.split("=", 1)
                    env_dict[k] = v
            stdio_args = list(args.stdio_args or [])
            if args.stdio_arg:
                print("[warning] --stdio-arg is deprecated; use --stdio-args")
                stdio_args.extend(args.stdio_arg)
            stdio = StdioServer(
                command=args.stdio_command,
                args=stdio_args,
                env=env_dict or None,
                expand_vars=args.expand_vars,
            )
            if args.stdio_tool:
                scan_result = await scanner.scan_stdio_server_tool(
                    stdio, args.stdio_tool, analyzers=selected_analyzers
                )
                results = await results_to_json([scan_result])
            else:
                scan_results = await scanner.scan_stdio_server_tools(
                    stdio, analyzers=selected_analyzers
                )
                results = await results_to_json(scan_results)

        elif args.scan_known_configs or args.config_path:
            cfg = _build_config(selected_analyzers)
            scanner = Scanner(cfg, rules_dir=args.rules_path)
            if args.config_path:
                auth = Auth.bearer(args.bearer_token) if args.bearer_token else None
                scan_results = await scanner.scan_mcp_config_file(
                    args.config_path,
                    analyzers=selected_analyzers,
                    auth=auth,
                    expand_vars_default=args.expand_vars,
                )
                results = await results_to_json(scan_results)
            else:
                auth = Auth.bearer(args.bearer_token) if args.bearer_token else None
                results_by_cfg = await scanner.scan_well_known_mcp_configs(
                    analyzers=selected_analyzers,
                    auth=auth,
                    expand_vars_default=args.expand_vars,
                )
                if args.raw:
                    output = {}
                    for cfg_path, scan_results in results_by_cfg.items():
                        output[cfg_path] = await results_to_json(scan_results)
                    print(json.dumps(output, indent=2))
                    return
                flattened = []
                for cfg_path, scan_results in results_by_cfg.items():
                    # Add config path and server info to each result
                    for result in scan_results:
                        # Extract server name from config path for display
                        config_name = (
                            cfg_path.split("/")[-1] if "/" in cfg_path else cfg_path
                        )
                        result.server_source = f"{config_name}"
                    flattened.extend(scan_results)
                results = await results_to_json(flattened)

        else:
            # Check if behavioral analyzer with source path
            if AnalyzerEnum.BEHAVIORAL in selected_analyzers and args.source_path:
                # Run behavioral analyzer on source code
                results = await _run_behavioral_analyzer_on_source(args.source_path)
            else:
                # Run the security scan against a server URL
                if args.bearer_token:
                    cfg = _build_config(selected_analyzers)
                    scanner = Scanner(cfg, rules_dir=args.rules_path)
                    results_raw = await scanner.scan_remote_server_tools(
                        args.server_url,
                        auth=Auth.bearer(args.bearer_token),
                        analyzers=selected_analyzers,
                    )
                    results = await results_to_json(results_raw)
                else:
                    cfg = _build_config(selected_analyzers, endpoint_url=args.endpoint_url)
                    scanner = Scanner(cfg, rules_dir=args.rules_path)
                    auth = Auth.bearer(args.bearer_token) if args.bearer_token else None
                    results_raw = await scanner.scan_remote_server_tools(
                        args.server_url, auth=auth, analyzers=selected_analyzers
                    )
                    results = await results_to_json(results_raw)

    except Exception as e:
        print(f"Error during scanning: {e}", file=sys.stderr)
        sys.exit(1)

    # Display the results using the new report generator
    if not args.raw and not args.detailed:
        # Choose an appropriate label for display based on scanning mode
        server_label = args.server_url
        if hasattr(args, "cmd") and args.cmd == "stdio":
            label_args = []
            if getattr(args, "stdio_arg", None):
                label_args.extend(args.stdio_arg)
            if getattr(args, "stdio_args", None):
                label_args.extend(args.stdio_args)
            server_label = f"stdio:{args.stdio_command} {' '.join(label_args)}".strip()
        elif hasattr(args, "cmd") and args.cmd == "config":
            server_label = args.config_path
        elif hasattr(args, "cmd") and args.cmd == "known-configs":
            server_label = "well-known-configs"
        elif hasattr(args, "cmd") and args.cmd == "prompts":
            server_label = args.server_url
        elif hasattr(args, "cmd") and args.cmd == "resources":
            server_label = args.server_url
        elif hasattr(args, "cmd") and args.cmd == "behavioral":
            server_label = f"behavioral:{args.source_path}"
        elif AnalyzerEnum.BEHAVIORAL in selected_analyzers and args.source_path:
            server_label = f"behavioral:{args.source_path}"
        elif args.stdio_command:
            label_args = []
            if getattr(args, "stdio_arg", None):
                label_args.extend(args.stdio_arg)
            if getattr(args, "stdio_args", None):
                label_args.extend(args.stdio_args)
            server_label = f"stdio:{args.stdio_command} {' '.join(label_args)}".strip()
        elif args.config_path:
            server_label = args.config_path
        elif args.scan_known_configs:
            server_label = "well-known-configs"

        # Handle prompts, resources, and instructions differently
        if hasattr(args, "cmd") and args.cmd == "prompts":
            if args.format == "table":
                display_prompt_results_table(results, server_label)
            else:
                display_prompt_results(results, server_label, detailed=False)
            return
        elif hasattr(args, "cmd") and args.cmd == "resources":
            if args.format == "table":
                display_resource_results_table(results, server_label)
            else:
                display_resource_results(results, server_label, detailed=False)
            return
        elif hasattr(args, "cmd") and args.cmd == "instructions":
            if args.format == "table":
                display_instructions_results_table(results, server_label)
            else:
                display_instructions_results(results, server_label, detailed=False)
            return

        results_dict = {
            "server_url": server_label,
            "scan_results": results,
            "requested_analyzers": selected_analyzers,
        }
        formatter = ReportGenerator(results_dict)

        if args.stats:
            stats = formatter.get_statistics()
            print("=== Scan Statistics ===")
            print(f"Total tools: {stats['total_tools']}")
            print(f"Safe tools: {stats['safe_tools']}")
            print(f"Unsafe tools: {stats['unsafe_tools']}")
            print(f"Severity breakdown: {stats['severity_counts']}")
            print(f"Analyzer stats: {stats['analyzer_stats']}")
            print()

        # Determine output format
        if args.format == "raw":
            output_format = OutputFormat.RAW
        elif args.format == "summary":
            output_format = OutputFormat.SUMMARY
        elif args.format == "detailed":
            output_format = OutputFormat.DETAILED
        elif args.format == "by_tool":
            output_format = OutputFormat.BY_TOOL
        elif args.format == "by_analyzer":
            output_format = OutputFormat.BY_ANALYZER
        elif args.format == "by_severity":
            output_format = OutputFormat.BY_SEVERITY
        elif args.format == "table":
            output_format = OutputFormat.TABLE
        else:
            output_format = OutputFormat.SUMMARY

        # Determine severity filter
        if args.severity_filter == "all":
            severity_filter = SeverityFilter.ALL
        elif args.severity_filter == "high":
            severity_filter = SeverityFilter.HIGH
        elif args.severity_filter == "unknown":
            severity_filter = SeverityFilter.UNKNOWN
        elif args.severity_filter == "medium":
            severity_filter = SeverityFilter.MEDIUM
        elif args.severity_filter == "low":
            severity_filter = SeverityFilter.LOW
        elif args.severity_filter == "safe":
            severity_filter = SeverityFilter.SAFE
        else:
            severity_filter = SeverityFilter.ALL

        # Generate and display report
        formatted_output = formatter.format_output(
            format_type=output_format,
            tool_filter=args.tool_filter,
            analyzer_filter=args.analyzer_filter,
            severity_filter=severity_filter,
            show_safe=not args.hide_safe,
        )
        print(formatted_output)

    elif args.raw:
        print(json.dumps(results, indent=2))
    else:
        # Choose an appropriate label for display based on scanning mode
        server_label = args.server_url
        if args.stdio_command:
            label_args = []
            if args.stdio_arg:
                label_args.extend(args.stdio_arg)
            if args.stdio_args:
                label_args.extend(args.stdio_args)
            server_label = f"stdio:{args.stdio_command} {' '.join(label_args)}".strip()
        elif args.config_path:
            server_label = args.config_path
        elif args.scan_known_configs:
            server_label = "well-known-configs"

        # Handle prompts, resources, and instructions with detailed view
        if hasattr(args, "cmd") and args.cmd == "prompts":
            display_prompt_results(results, server_label, detailed=args.detailed)
        elif hasattr(args, "cmd") and args.cmd == "resources":
            display_resource_results(results, server_label, detailed=args.detailed)
        elif hasattr(args, "cmd") and args.cmd == "instructions":
            display_instructions_results(results, server_label, detailed=args.detailed)
        else:
            results_dict = {"server_url": server_label, "scan_results": results}
            display_results(results_dict, detailed=args.detailed)


def cli_entry_point():
    """Entry point for the mcp-scanner CLI command."""
    import sys
    import logging
    import warnings

    # Suppress warnings from MCP library cleanup issues
    warnings.filterwarnings("ignore", category=RuntimeWarning, message=".*coroutine.*never awaited.*")
    warnings.filterwarnings("ignore", category=RuntimeWarning, message=".*async.*generator.*")

    # Suppress asyncio shutdown errors from MCP library cleanup bugs
    def custom_exception_handler(loop, context):
        exception = context.get("exception")
        message = context.get("message", "")

        # Suppress RuntimeError from MCP library task cleanup
        if isinstance(exception, RuntimeError) and "cancel scope" in str(exception):
            return
        # Suppress task destroyed warnings
        if "Task was destroyed but it is pending" in message:
            return
        # Suppress other MCP library cleanup errors
        if "streamablehttp_client" in message or "async_generator" in message:
            return
        # For other exceptions, use default handling
        loop.default_exception_handler(context)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.set_exception_handler(custom_exception_handler)

    try:
        loop.run_until_complete(main())
    finally:
        # Suppress warnings during loop close
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            loop.close()


if __name__ == "__main__":
    asyncio.run(main())
