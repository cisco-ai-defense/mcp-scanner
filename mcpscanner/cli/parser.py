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

Each subcommand is built by its own ``_add_*`` function, and the option groups
several subcommands share -- output formatting, remote server connection,
stdio launch, package sandboxing -- are factored into ``_add_*_options``
helpers. Subcommands are registered before the global options because argparse
renders help in registration order.
"""

import argparse

FORMAT_CHOICES = [
    "raw",
    "summary",
    "detailed",
    "by_tool",
    "by_analyzer",
    "by_severity",
    "table",
]

ANALYZER_FILTER_CHOICES = [
    "api_analyzer",
    "yara_analyzer",
    "llm_analyzer",
    "behavioral_analyzer",
    "virustotal_analyzer",
    "vulnerable_package_analyzer",
]

SEVERITY_CHOICES = ["all", "high", "unknown", "medium", "low", "safe"]

DEFAULT_MIME_TYPES = "text/plain,text/html"

EPILOG = """Examples:
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
        """


# --- shared option groups ----------------------------------------------------


def _add_output_options(p: argparse.ArgumentParser) -> None:
    """Result destination and rendering, identical on every scan subcommand."""
    p.add_argument("--output", "-o", help="Save scan results to a file")
    p.add_argument("--verbose", "-v", action="store_true", help="Print verbose output")
    p.add_argument("--raw", "-r", action="store_true", help="Print raw JSON output")
    p.add_argument(
        "--detailed", "-d", action="store_true", help="Show detailed results"
    )
    p.add_argument(
        "--format",
        choices=FORMAT_CHOICES,
        default="summary",
        help="Output format (default: %(default)s)",
    )


def _add_server_options(
    p: argparse.ArgumentParser,
    *,
    bearer_help: str = "Bearer token for authentication",
    headers: bool = True,
) -> None:
    """How to reach and authenticate against a remote MCP server."""
    p.add_argument(
        "--server-url",
        required=True,
        help="URL of the MCP server to scan",
    )
    p.add_argument("--bearer-token", help=bearer_help)
    if headers:
        p.add_argument(
            "--header",
            action="append",
            dest="custom_headers",
            metavar="NAME:VALUE",
            help="Custom HTTP header in format 'Name: Value'. Can be specified multiple times.",
        )


def _add_mime_types(p: argparse.ArgumentParser, help_text: str) -> None:
    p.add_argument("--mime-types", default=DEFAULT_MIME_TYPES, help=help_text)


def _add_stdio_options(p: argparse.ArgumentParser, *, required_command: bool) -> None:
    """How to launch a local stdio MCP server.

    The top-level parser accepts these without a command so the legacy
    flag-only invocation keeps working; the ``stdio`` subcommand requires one.
    """
    p.add_argument(
        "--stdio-command",
        required=True if required_command else False,
        help=(
            "Command to run the stdio-based MCP server (e.g., 'uvx')"
            if required_command
            else "Run a stdio-based MCP server using the given command (e.g., 'uvx')"
        ),
    )
    p.add_argument(
        "--stdio-args",
        type=str,
        default="",
        help="Arguments passed to the stdio command (comma-separated, e.g., '--from,mcp-server-fetch,mcp-server-fetch')",
    )
    p.add_argument(
        "--stdio-arg",
        action="append",
        help="Repeatable single argument (e.g., --stdio-arg=--from --stdio-arg=pkg). More reliable than --stdio-args for complex package names.",
    )
    p.add_argument(
        "--stderr-file",
        help="Redirect server stderr to this file (useful for debugging startup messages that may corrupt JSON output)",
    )
    p.add_argument(
        "--stdio-env",
        action="append",
        default=[],
        help="Environment variables for the stdio server in KEY=VALUE form; can be repeated",
    )
    p.add_argument(
        "--stdio-tool",
        help="If provided, only scan this specific tool name on the stdio server",
    )


def _add_package_scan_options(
    p: argparse.ArgumentParser, *, rebuild_help: str, no_docker_help: str
) -> None:
    """Version pinning and sandbox controls shared by the pypi and npm scans."""
    p.add_argument("--version", help="Specific package version (default: latest)")
    _add_output_options(p)
    p.add_argument("--rebuild-image", action="store_true", help=rebuild_help)
    p.add_argument("--no-docker", action="store_true", help=no_docker_help)


# --- subcommands -------------------------------------------------------------


def _add_static(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser(
        "static", help="Scan pre-generated MCP JSON files (offline/CI-CD mode)"
    )
    p.add_argument("--tools", help="Path to tools JSON file (MCP tools/list output)")
    p.add_argument(
        "--prompts", help="Path to prompts JSON file (MCP prompts/list output)"
    )
    p.add_argument(
        "--resources", help="Path to resources JSON file (MCP resources/list output)"
    )
    _add_mime_types(
        p,
        "Comma-separated MIME types for resource scanning (default: %(default)s)",
    )


def _add_remote(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser(
        "remote", help="Scan a remote MCP server (SSE or streamable HTTP)"
    )
    _add_server_options(
        p,
        bearer_help="Bearer token to use for remote MCP server authentication (Authorization: Bearer <token>)",
    )


def _add_prompts(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("prompts", help="Scan prompts on an MCP server")
    _add_server_options(p)
    p.add_argument(
        "--prompt-name",
        help="Scan a specific prompt by name (if not provided, scans all prompts)",
    )


def _add_resources(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("resources", help="Scan resources on an MCP server")
    _add_server_options(p)
    p.add_argument(
        "--resource-uri",
        help="Scan a specific resource by URI (if not provided, scans all resources)",
    )
    _add_mime_types(
        p, "Comma-separated list of allowed MIME types (default: %(default)s)"
    )


def _add_instructions(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("instructions", help="Scan server instructions on an MCP server")
    _add_server_options(p, headers=False)


def _add_virustotal(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser(
        "virustotal",
        help="Scan files or directories for malware using VirusTotal",
    )
    p.add_argument(
        "scan_path", help="Path to a file or directory to scan with VirusTotal"
    )
    _add_output_options(p)


def _add_behavioral(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser(
        "behavioral",
        help="Scan MCP server source code for docstring/behavior mismatches",
    )
    p.add_argument(
        "source_path", help="Path to MCP server source code file or directory"
    )
    _add_output_options(p)


def _add_pypi_scan(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser(
        "pypi-scan",
        help="Download and scan a PyPI package in a Docker sandbox",
    )
    p.add_argument("package", help="PyPI package name (e.g., flask)")
    _add_package_scan_options(
        p,
        rebuild_help="Force rebuild of the Docker scanner image",
        no_docker_help=(
            "Run the PyPI scan locally without Docker. Intended for SDK / CI "
            "environments where Docker is unavailable; archives are size-capped "
            "and extracted via tarfile data filter. The package's own code is "
            "never executed, but local mode is a weaker sandbox than Docker."
        ),
    )


def _add_npm_scan(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser(
        "npm-scan",
        help="Download and scan an npm package in a Docker sandbox",
    )
    p.add_argument(
        "package",
        help="npm package name (supports @scope/name, e.g. @modelcontextprotocol/server-everything)",
    )
    _add_package_scan_options(
        p,
        rebuild_help="Force rebuild of the npm Docker scanner image",
        no_docker_help=(
            "Run the npm scan locally without Docker. Intended for SDK / CI "
            "environments where Docker is unavailable; tarballs are size-capped "
            "and extracted via tarfile data filter. The package's JS is never "
            "executed (only parsed), but local mode is a weaker sandbox than Docker."
        ),
    )


def _add_vulnerable_package(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser(
        "vulnerable-package",
        help="Scan Python dependencies for known vulnerabilities using pip-audit",
    )
    p.add_argument(
        "scan_path",
        help="Path to a project directory or requirements file to audit",
    )
    p.add_argument(
        "--vulnerability-service",
        choices=["pypi", "osv"],
        default=None,
        help="Vulnerability service to query (default: pypi)",
    )
    p.add_argument(
        "--fix", action="store_true", help="Automatically fix vulnerable dependencies"
    )
    p.add_argument(
        "--no-deps",
        action="store_true",
        dest="no_deps",
        help="Skip transitive dependency resolution (only for fully-resolved/pinned inputs)",
    )
    p.add_argument(
        "--disable-pip",
        action="store_true",
        dest="disable_pip",
        help="Disable pip for dependency resolution (use with --no-deps for pinned inputs)",
    )
    _add_output_options(p)


def _add_stdio(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser(
        "stdio", help="Scan an MCP server via stdio (local command execution)"
    )
    _add_stdio_options(p, required_command=True)


def _add_config(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser(
        "config", help="Scan all servers defined in a specific MCP config file"
    )
    p.add_argument(
        "--config-path",
        required=True,
        help="Path to MCP config file (e.g., ~/.codeium/windsurf/mcp_config.json)",
    )
    p.add_argument("--bearer-token", help="Bearer token for authentication")


def _add_known_configs(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser(
        "known-configs",
        help="Scan all well-known MCP client config files on this machine",
    )
    p.add_argument("--bearer-token", help="Bearer token for authentication")


SUBCOMMANDS = (
    _add_static,
    _add_remote,
    _add_prompts,
    _add_resources,
    _add_instructions,
    _add_virustotal,
    _add_behavioral,
    _add_pypi_scan,
    _add_npm_scan,
    _add_vulnerable_package,
    _add_stdio,
    _add_config,
    _add_known_configs,
)


# --- global options ----------------------------------------------------------


def _add_credentials(parser: argparse.ArgumentParser) -> None:
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


def _add_analyzer_selection(parser: argparse.ArgumentParser) -> None:
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


def _add_global_output(parser: argparse.ArgumentParser) -> None:
    """Like ``_add_output_options`` but with --log-level and its own --raw wording."""
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


def _add_legacy_targets(parser: argparse.ArgumentParser) -> None:
    """Flag-only forms of the scan targets, kept for pre-subcommand invocations."""
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
    _add_stdio_options(parser, required_command=False)
    parser.add_argument(
        "--bearer-token",
        help="Bearer token to use for remote MCP server authentication (Authorization: Bearer <token>)",
    )


def _add_result_filters(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--format",
        choices=FORMAT_CHOICES,
        default="summary",
        help="Output format (default: %(default)s)",
    )
    parser.add_argument(
        "--tool-filter", help="Filter results by tool name (partial match)"
    )
    parser.add_argument(
        "--analyzer-filter",
        choices=ANALYZER_FILTER_CHOICES,
        help="Filter results by specific analyzer",
    )
    parser.add_argument(
        "--severity-filter",
        choices=SEVERITY_CHOICES,
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


def build_parser() -> argparse.ArgumentParser:
    """Construct the full CLI parser, subcommands and global options."""
    parser = argparse.ArgumentParser(
        description="MCP Security Scanner - Comprehensive security analysis for MCP servers",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    subparsers = parser.add_subparsers(dest="cmd")
    for add_subcommand in SUBCOMMANDS:
        add_subcommand(subparsers)

    _add_credentials(parser)
    _add_analyzer_selection(parser)
    _add_global_output(parser)
    _add_legacy_targets(parser)
    _add_result_filters(parser)

    return parser
