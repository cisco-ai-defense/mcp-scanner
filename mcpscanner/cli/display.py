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

"""Human-readable renderers for each kind of scan result."""

from typing import Any, Dict, List

from mcpscanner.utils.logging_config import get_logger

logger = get_logger(__name__)


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
                                print(
                                    f"      Sub-Technique: {aisubtech} - {aisubtech_name}"
                                )
                            if description:
                                print(f"      Description: {description}")

                        print()
                        finding_num += 1
            print()


def display_prompt_results_table(
    results: List[Dict[str, Any]], server_url: str
) -> None:
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

        table_data.append(
            [status_icon, prompt_name, desc_short, findings_count, status]
        )

    headers = ["Status", "Prompt Name", "Description", "Findings", "Scan Status"]
    print(tabulate(table_data, headers=headers, tablefmt="grid"))

    # Summary
    safe = sum(1 for r in results if r.get("is_safe", False))
    unsafe = sum(1 for r in results if not r.get("is_safe", False))
    print(f"\n📊 Summary: {len(results)} total | {safe} safe | {unsafe} unsafe")


def display_resource_results_table(
    results: List[Dict[str, Any]], server_url: str
) -> None:
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
        findings_count = (
            len(result.get("findings", [])) if status == "completed" else "-"
        )

        table_data.append(
            [status_icon, resource_name, uri_short, mime_type, findings_count, status]
        )

    headers = ["Status", "Resource Name", "URI", "MIME Type", "Findings", "Scan Status"]
    print(tabulate(table_data, headers=headers, tablefmt="grid"))

    # Summary
    completed = [r for r in results if r.get("status") == "completed"]
    skipped = [r for r in results if r.get("status") == "skipped"]
    failed = [r for r in results if r.get("status") == "failed"]
    safe = sum(1 for r in completed if r.get("is_safe", False))
    unsafe = sum(1 for r in completed if not r.get("is_safe", False))

    print(
        f"\n📊 Summary: {len(results)} total | {len(completed)} scanned | {len(skipped)} skipped | {len(failed)} failed"
    )
    if completed:
        print(f"   Security: {safe} safe | {unsafe} unsafe")


def display_prompt_results(
    results: List[Dict[str, Any]], server_url: str, detailed: bool = False
) -> None:
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
            if prompt.get("prompt_description"):
                desc = prompt["prompt_description"]
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
                        threats = ", ".join(
                            [
                                t.replace("_", " ").title()
                                for t in details["primary_threats"]
                            ]
                        )
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
                            print(
                                f"      Sub-Technique: {aisubtech} - {aisubtech_name}"
                            )
                        if description:
                            print(f"      Description: {description}")
                    print()
            print()

    # Display safe prompts if detailed
    if detailed and safe_prompts:
        print("\n=== Safe Prompts ===\n")
        for i, prompt in enumerate(safe_prompts, 1):
            print(f"{i}. {prompt.get('prompt_name', 'Unknown')}")
            if prompt.get("prompt_description"):
                desc = prompt["prompt_description"]
                print(f"   Description: {desc[:80]}{'...' if len(desc) > 80 else ''}")
            print()


def display_resource_results(
    results: List[Dict[str, Any]], server_url: str, detailed: bool = False
) -> None:
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
                            threats = ", ".join(
                                [
                                    t.replace("_", " ").title()
                                    for t in details["primary_threats"]
                                ]
                            )
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
                                print(
                                    f"      Sub-Technique: {aisubtech} - {aisubtech_name}"
                                )
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


def display_instructions_results_table(
    results: List[Dict[str, Any]], server_url: str
) -> None:
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
        instructions_preview = (
            result.get("instructions", "")[:50] + "..."
            if len(result.get("instructions", "")) > 50
            else result.get("instructions", "")
        )

        table_data.append(
            [
                status_icon,
                server_name,
                protocol_version,
                instructions_preview,
                findings_count,
                status,
            ]
        )

    headers = [
        "Status",
        "Server Name",
        "Protocol",
        "Instructions Preview",
        "Findings",
        "Scan Status",
    ]
    print(tabulate(table_data, headers=headers, tablefmt="grid"))

    # Summary
    safe = sum(1 for r in results if r.get("is_safe", False))
    unsafe = sum(1 for r in results if not r.get("is_safe", False))
    print(f"\n📊 Summary: {len(results)} scanned | {safe} safe | {unsafe} unsafe")


def display_instructions_results(
    results: List[Dict[str, Any]], server_url: str, detailed: bool = False
) -> None:
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
            instructions_text = instr.get("instructions", "")
            if instructions_text:
                preview = (
                    instructions_text[:100] + "..."
                    if len(instructions_text) > 100
                    else instructions_text
                )
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
                        threats = ", ".join(
                            [
                                t.replace("_", " ").title()
                                for t in details["primary_threats"]
                            ]
                        )
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
                            print(
                                f"      Sub-Technique: {aisubtech} - {aisubtech_name}"
                            )
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
            instructions_text = instr.get("instructions", "")
            if instructions_text:
                preview = (
                    instructions_text[:100] + "..."
                    if len(instructions_text) > 100
                    else instructions_text
                )
                print(f"   Instructions: {preview}")
            print()
