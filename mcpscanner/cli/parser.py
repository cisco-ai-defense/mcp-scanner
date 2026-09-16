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

"""Argument parser for the ``mcp-scanner`` command line.

Kept apart from execution so the 13 subcommands and their ~100 options can be
introspected (and tested) without running a scan.
"""

import argparse


def build_parser() -> argparse.ArgumentParser:
    """Construct the full CLI parser, subcommands and global options."""
    parser = argparse.ArgumentParser(
        description="MCP Security Scanner - Comprehensive security analysis for MCP servers",
        epilog="""Examples:
  # Live server scanning:
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

  # Static file scanning (CI/CD friendly):
  %(prog)s static --tools tools.json --analyzers yara                         # Scan static tools file
  %(prog)s static --prompts prompts.json --analyzers llm                     # Scan prompts file
  %(prog)s static --resources resources.json --analyzers yara                # Scan resources file
  %(prog)s static --tools t.json --prompts p.json --analyzers yara,llm,api   # Scan all three types
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Subcommands for scan modes (remote, stdio, config, known-configs, prompts, resources, instructions, static)
    subparsers = parser.add_subparsers(dest="cmd")

    # Static file scanning subcommand
    p_static = subparsers.add_parser(
        "static", help="Scan pre-generated MCP JSON files (offline/CI-CD mode)"
    )
    p_static.add_argument(
        "--tools",
        help="Path to tools JSON file (MCP tools/list output)",
    )
    p_static.add_argument(
        "--prompts",
        help="Path to prompts JSON file (MCP prompts/list output)",
    )
    p_static.add_argument(
        "--resources",
        help="Path to resources JSON file (MCP resources/list output)",
    )
    p_static.add_argument(
        "--mime-types",
        default="text/plain,text/html",
        help="Comma-separated MIME types for resource scanning (default: %(default)s)",
    )

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
    p_prompts = subparsers.add_parser("prompts", help="Scan prompts on an MCP server")
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

    # VirusTotal subcommand - scan files/directories for malware
    p_virustotal = subparsers.add_parser(
        "virustotal",
        help="Scan files or directories for malware using VirusTotal",
    )
    p_virustotal.add_argument(
        "scan_path",
        help="Path to a file or directory to scan with VirusTotal",
    )
    p_virustotal.add_argument(
        "--output", "-o", help="Save scan results to a file"
    )
    p_virustotal.add_argument(
        "--verbose", "-v", action="store_true", help="Print verbose output"
    )
    p_virustotal.add_argument(
        "--raw", "-r", action="store_true", help="Print raw JSON output"
    )
    p_virustotal.add_argument(
        "--detailed", "-d", action="store_true", help="Show detailed results"
    )
    p_virustotal.add_argument(
        "--format",
        choices=[
            "raw", "summary", "detailed", "by_tool",
            "by_analyzer", "by_severity", "table",
        ],
        default="summary",
        help="Output format (default: %(default)s)",
    )

    # Behavioral subcommand - scan local source code
    p_behavioral = subparsers.add_parser(
        "behavioral",
        help="Scan MCP server source code for docstring/behavior mismatches",
    )
    p_behavioral.add_argument(
        "source_path",
        help="Path to MCP server source code file or directory",
    )
    p_behavioral.add_argument(
        "--output",
        "-o",
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

    # PyPI package scan subcommand (Docker-sandboxed by default)
    p_pypi = subparsers.add_parser(
        "pypi-scan",
        help="Download and scan a PyPI package in a Docker sandbox",
    )
    p_pypi.add_argument("package", help="PyPI package name (e.g., flask)")
    p_pypi.add_argument(
        "--version", help="Specific package version (default: latest)"
    )
    p_pypi.add_argument(
        "--output", "-o", help="Save scan results to a file"
    )
    p_pypi.add_argument(
        "--verbose", "-v", action="store_true", help="Print verbose output"
    )
    p_pypi.add_argument(
        "--raw", "-r", action="store_true", help="Print raw JSON output"
    )
    p_pypi.add_argument(
        "--detailed", "-d", action="store_true", help="Show detailed results"
    )
    p_pypi.add_argument(
        "--format",
        choices=[
            "raw", "summary", "detailed", "by_tool",
            "by_analyzer", "by_severity", "table",
        ],
        default="summary",
        help="Output format (default: %(default)s)",
    )
    p_pypi.add_argument(
        "--rebuild-image",
        action="store_true",
        help="Force rebuild of the Docker scanner image",
    )
    p_pypi.add_argument(
        "--no-docker",
        action="store_true",
        help=(
            "Run the PyPI scan locally without Docker. Intended for SDK / CI "
            "environments where Docker is unavailable; archives are size-capped "
            "and extracted via tarfile data filter. The package's own code is "
            "never executed, but local mode is a weaker sandbox than Docker."
        ),
    )

    # npm package scan subcommand (Docker-sandboxed by default; --no-docker
    # opt-in for SDK environments).
    p_npm = subparsers.add_parser(
        "npm-scan",
        help="Download and scan an npm package in a Docker sandbox",
    )
    p_npm.add_argument(
        "package",
        help="npm package name (supports @scope/name, e.g. @modelcontextprotocol/server-everything)",
    )
    p_npm.add_argument(
        "--version", help="Specific package version (default: latest)"
    )
    p_npm.add_argument(
        "--output", "-o", help="Save scan results to a file"
    )
    p_npm.add_argument(
        "--verbose", "-v", action="store_true", help="Print verbose output"
    )
    p_npm.add_argument(
        "--raw", "-r", action="store_true", help="Print raw JSON output"
    )
    p_npm.add_argument(
        "--detailed", "-d", action="store_true", help="Show detailed results"
    )
    p_npm.add_argument(
        "--format",
        choices=[
            "raw", "summary", "detailed", "by_tool",
            "by_analyzer", "by_severity", "table",
        ],
        default="summary",
        help="Output format (default: %(default)s)",
    )
    p_npm.add_argument(
        "--rebuild-image",
        action="store_true",
        help="Force rebuild of the npm Docker scanner image",
    )
    p_npm.add_argument(
        "--no-docker",
        action="store_true",
        help=(
            "Run the npm scan locally without Docker. Intended for SDK / CI "
            "environments where Docker is unavailable; tarballs are size-capped "
            "and extracted via tarfile data filter. The package's JS is never "
            "executed (only parsed), but local mode is a weaker sandbox than Docker."
        ),
    )

    # vulnerable-package subcommand - scan Python dependencies for known vulnerabilities
    p_vuln_pkgs = subparsers.add_parser(
        "vulnerable-package",
        help="Scan Python dependencies for known vulnerabilities using pip-audit",
    )
    p_vuln_pkgs.add_argument(
        "scan_path",
        help="Path to a project directory or requirements file to audit",
    )
    p_vuln_pkgs.add_argument(
        "--vulnerability-service",
        choices=["pypi", "osv"],
        default=None,
        help="Vulnerability service to query (default: pypi)",
    )
    p_vuln_pkgs.add_argument(
        "--fix", action="store_true", help="Automatically fix vulnerable dependencies"
    )
    p_vuln_pkgs.add_argument(
        "--no-deps",
        action="store_true",
        dest="no_deps",
        help="Skip transitive dependency resolution (only for fully-resolved/pinned inputs)",
    )
    p_vuln_pkgs.add_argument(
        "--disable-pip",
        action="store_true",
        dest="disable_pip",
        help="Disable pip for dependency resolution (use with --no-deps for pinned inputs)",
    )
    p_vuln_pkgs.add_argument(
        "--output", "-o", help="Save scan results to a file"
    )
    p_vuln_pkgs.add_argument(
        "--verbose", "-v", action="store_true", help="Print verbose output"
    )
    p_vuln_pkgs.add_argument(
        "--raw", "-r", action="store_true", help="Print raw JSON output"
    )
    p_vuln_pkgs.add_argument(
        "--detailed", "-d", action="store_true", help="Show detailed results"
    )
    p_vuln_pkgs.add_argument(
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
        type=str,
        default="",
        help="Arguments passed to the stdio command (comma-separated, e.g., '--from,mcp-server-fetch,mcp-server-fetch')",
    )
    p_stdio.add_argument(
        "--stdio-arg",
        action="append",
        help="Repeatable single argument (e.g., --stdio-arg=--from --stdio-arg=pkg). More reliable than --stdio-args for complex package names.",
    )
    p_stdio.add_argument(
        "--stderr-file",
        help="Redirect server stderr to this file (useful for debugging startup messages that may corrupt JSON output)",
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
        "known-configs",
        help="Scan all well-known MCP client config files on this machine",
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
        "--stdio-timeout",
        type=int,
        help="Timeout in seconds for stdio server connections (overrides MCP_SCANNER_STDIO_TIMEOUT environment variable, default: 60)",
    )

    parser.add_argument(
        "--analyzers",
        default="api,yara,llm",
        help="Comma-separated list of analyzers to run. Options: api, yara, llm, behavioral, virustotal, readiness, vulnerable_package, meta (default: %(default)s)",
    )

    parser.add_argument(
        "--enable-meta",
        action="store_true",
        help=(
            "Enable the LLM meta-analyzer for second-pass analysis. "
            "Reviews findings from all other analyzers to filter false positives, "
            "prioritize by actual risk, and correlate related findings. "
            "Requires MCP_SCANNER_LLM_API_KEY. Adds 'meta' to the analyzer list."
        ),
    )

    parser.add_argument("--output", "-o", help="Save scan results to a file")
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Print verbose output"
    )
    parser.add_argument(
        "--log-level",
        choices=["debug", "info", "warning", "error", "critical"],
        default=None,
        help="Set log level for the mcpscanner library (overrides --verbose). "
        "Useful for suppressing noisy output in CI/CD pipelines.",
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
            "windows: expand %%VAR%% (Windows style only). "
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
        type=str,
        default="",
        help="Arguments passed to the stdio command (comma-separated, e.g., '--from,mcp-server-fetch,mcp-server-fetch')",
    )
    parser.add_argument(
        "--stdio-arg",
        action="append",
        help="Repeatable single argument (e.g., --stdio-arg=--from --stdio-arg=pkg). More reliable than --stdio-args for complex package names.",
    )
    parser.add_argument(
        "--stderr-file",
        help="Redirect server stderr to this file (useful for debugging startup messages that may corrupt JSON output)",
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
        choices=[
            "api_analyzer",
            "yara_analyzer",
            "llm_analyzer",
            "behavioral_analyzer",
            "virustotal_analyzer",
            "vulnerable_package_analyzer",
        ],
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

    return parser
