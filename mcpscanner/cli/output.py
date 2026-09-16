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

"""Rendering of scan results to the terminal.

Three shapes come out of a scan -- the default report, ``--raw`` JSON, and
``--detailed`` -- and each needs a label naming what was scanned.
"""

import json
from typing import Any, List

from mcpscanner.core.models import AnalyzerEnum
from mcpscanner.core.report_generator import (
    OutputFormat,
    ReportGenerator,
    SeverityFilter,
)

from .context import CommandContext
from .display import (
    display_instructions_results,
    display_instructions_results_table,
    display_prompt_results,
    display_prompt_results_table,
    display_resource_results,
    display_resource_results_table,
    display_results,
)

#: ``--format`` value to the report generator's enum.
_OUTPUT_FORMATS = {
    "raw": OutputFormat.RAW,
    "summary": OutputFormat.SUMMARY,
    "detailed": OutputFormat.DETAILED,
    "by_tool": OutputFormat.BY_TOOL,
    "by_analyzer": OutputFormat.BY_ANALYZER,
    "by_severity": OutputFormat.BY_SEVERITY,
    "table": OutputFormat.TABLE,
}

#: ``--severity-filter`` value to the report generator's enum.
_SEVERITY_FILTERS = {
    "all": SeverityFilter.ALL,
    "high": SeverityFilter.HIGH,
    "unknown": SeverityFilter.UNKNOWN,
    "medium": SeverityFilter.MEDIUM,
    "low": SeverityFilter.LOW,
    "safe": SeverityFilter.SAFE,
}


def _report_label(args: Any, selected_analyzers: List[AnalyzerEnum]) -> str:
    """Name the scan target for the default report header."""
    server_label = args.server_url
    if hasattr(args, "cmd") and args.cmd == "stdio":
        label_args = []
        if getattr(args, "stdio_arg", None):
            label_args.extend(args.stdio_arg)
        if getattr(args, "stdio_args", None):
            label_args.extend([a for a in args.stdio_args.split(",") if a])
        server_label = f"stdio:{args.stdio_command} {' '.join(label_args)}".strip()
    elif hasattr(args, "cmd") and args.cmd == "config":
        server_label = args.config_path
    elif hasattr(args, "cmd") and args.cmd == "known-configs":
        server_label = "well-known-configs"
    elif hasattr(args, "cmd") and args.cmd == "prompts":
        server_label = args.server_url
    elif hasattr(args, "cmd") and args.cmd == "resources":
        server_label = args.server_url
    elif hasattr(args, "cmd") and args.cmd == "virustotal":
        server_label = f"virustotal:{args.scan_path}"
    elif hasattr(args, "cmd") and args.cmd == "vulnerable-package":
        server_label = f"vulnerable-package:{args.scan_path}"
    elif hasattr(args, "cmd") and args.cmd == "behavioral":
        server_label = f"behavioral:{args.source_path}"
    elif hasattr(args, "cmd") and args.cmd == "pypi-scan":
        pkg_spec = args.package
        if getattr(args, "version", None):
            pkg_spec = f"{args.package}=={args.version}"
        server_label = f"pypi:{pkg_spec}"
    elif hasattr(args, "cmd") and args.cmd == "npm-scan":
        pkg_spec = args.package
        if getattr(args, "version", None):
            pkg_spec = f"{args.package}@{args.version}"
        server_label = f"npm:{pkg_spec}"
    elif AnalyzerEnum.BEHAVIORAL in selected_analyzers and args.source_path:
        server_label = f"behavioral:{args.source_path}"
    elif args.stdio_command:
        label_args = []
        if getattr(args, "stdio_arg", None):
            label_args.extend(args.stdio_arg)
        if getattr(args, "stdio_args", None):
            label_args.extend([a for a in args.stdio_args.split(",") if a])
        server_label = f"stdio:{args.stdio_command} {' '.join(label_args)}".strip()
    elif args.config_path:
        server_label = args.config_path
    elif args.scan_known_configs:
        server_label = "well-known-configs"
    return server_label


def _detailed_label(args: Any) -> str:
    """Name the scan target for the ``--detailed`` view.

    Deliberately not ``_report_label``: this chain tests fewer subcommands
    and tests them in a different order, so the two disagree for at least
    the ``config`` and ``known-configs`` subcommands. Reconciling them is a
    behavior change, not a refactor.
    """
    # Choose an appropriate label for display based on scanning mode
    server_label = args.server_url
    if args.stdio_command:
        label_args = []
        if args.stdio_arg:
            label_args.extend(args.stdio_arg)
        if args.stdio_args:
            label_args.extend([a for a in args.stdio_args.split(",") if a])
        server_label = f"stdio:{args.stdio_command} {' '.join(label_args)}".strip()
    elif args.config_path:
        server_label = args.config_path
    elif args.scan_known_configs:
        server_label = "well-known-configs"
    elif hasattr(args, "cmd") and args.cmd == "behavioral":
        server_label = f"behavioral:{args.source_path}"
    elif hasattr(args, "cmd") and args.cmd == "pypi-scan":
        pkg_spec = args.package
        if getattr(args, "version", None):
            pkg_spec = f"{args.package}=={args.version}"
        server_label = f"pypi:{pkg_spec}"
    elif hasattr(args, "cmd") and args.cmd == "npm-scan":
        pkg_spec = args.package
        if getattr(args, "version", None):
            pkg_spec = f"{args.package}@{args.version}"
        server_label = f"npm:{pkg_spec}"
    elif hasattr(args, "cmd") and args.cmd == "vulnerable-package":
        server_label = f"vulnerable-package:{args.scan_path}"
    return server_label


def render(ctx: CommandContext, results: Any) -> None:
    """Write the scan results in whichever shape the flags asked for."""
    args = ctx.args
    selected_analyzers = ctx.analyzers

    if not args.raw and not args.detailed:
        _render_report(args, selected_analyzers, results)
    elif args.raw:
        print(json.dumps(results, indent=2))
    else:
        _render_detailed(args, results)


def _render_report(
    args: Any, selected_analyzers: List[AnalyzerEnum], results: Any
) -> None:
    """The default view: a generated report, optionally preceded by stats."""
    server_label = _report_label(args, selected_analyzers)

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

    is_vuln_pkg_scan = hasattr(args, "cmd") and args.cmd == "vulnerable-package"
    if is_vuln_pkg_scan:
        results_dict = {
            "scan_target": server_label,
            "scan_results": results,
            "requested_analyzers": selected_analyzers,
        }
    else:
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

    output_format = _OUTPUT_FORMATS.get(args.format, OutputFormat.SUMMARY)
    severity_filter = _SEVERITY_FILTERS.get(args.severity_filter, SeverityFilter.ALL)

    # Generate and display report
    formatted_output = formatter.format_output(
        format_type=output_format,
        tool_filter=args.tool_filter,
        analyzer_filter=args.analyzer_filter,
        severity_filter=severity_filter,
        show_safe=not args.hide_safe,
    )
    print(formatted_output)


def _render_detailed(args: Any, results: Any) -> None:
    """The ``--detailed`` view, which bypasses the report generator."""
    server_label = _detailed_label(args)

    # Handle prompts, resources, and instructions with detailed view
    if hasattr(args, "cmd") and args.cmd == "prompts":
        display_prompt_results(results, server_label, detailed=args.detailed)
    elif hasattr(args, "cmd") and args.cmd == "resources":
        display_resource_results(results, server_label, detailed=args.detailed)
    elif hasattr(args, "cmd") and args.cmd == "instructions":
        display_instructions_results(results, server_label, detailed=args.detailed)
    elif hasattr(args, "cmd") and args.cmd == "vulnerable-package":
        results_dict = {
            "scan_target": server_label,
            "scan_results": results,
            "requested_analyzers": [AnalyzerEnum.VULNERABLE_PACKAGE],
        }
        formatter = ReportGenerator(results_dict)
        print(formatter.format_output(format_type=OutputFormat.DETAILED))
    else:
        results_dict = {"server_url": server_label, "scan_results": results}
        display_results(results_dict, detailed=args.detailed)
