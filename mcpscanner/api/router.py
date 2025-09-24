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

from typing import List, Optional, Union

from fastapi import APIRouter, Depends, HTTPException, Request

from ..core.models import (
    AllToolsScanResponse,
    AnalyzerEnum,
    APIScanRequest,
    FormattedScanResponse,
    OutputFormat,
    SeverityFilter,
    SpecificToolScanRequest,
    ToolScanResult,
)
from ..core.report_generator import ReportGenerator
from ..core.result import (
    ScanResult,
    get_highest_severity,
    group_findings_by_analyzer,
    process_scan_results,
)
from ..core.scanner import Scanner, ScannerFactory
from ..utils.logging_config import get_logger

router = APIRouter()
logger = get_logger(__name__)


def get_scanner() -> ScannerFactory:
    """
    Dependency injection placeholder for the ScannerFactory.
    This will be overridden by the application that uses this router.
    """
    raise NotImplementedError(
        "This dependency must be overridden in the main application."
    )


def _convert_scanner_result_to_api_result(
    scanner_result: ScanResult, scanner: Scanner
) -> ToolScanResult:
    """Convert a scanner result to an API result with grouped analyzer findings."""
    analyzer_groups = group_findings_by_analyzer(scanner_result.findings)
    grouped_findings = {}

    # Define the default analyzers that should always appear in the output.
    # The key is the display name, the value is the internal name used in findings.
    default_analyzers = {
        "api_analyzer": "API",
        "yara_analyzer": "YARA",
        "llm_analyzer": "LLM",
    }

    # Discover custom analyzers from the scanner instance.
    custom_analyzers = {a.name: a.name for a in scanner.get_custom_analyzers()}

    # Combine default and custom analyzers for the final map.
    all_analyzers_map = {**default_analyzers, **custom_analyzers}

    for display_name, internal_name in all_analyzers_map.items():
        vulns = analyzer_groups.get(internal_name, [])
        logger.debug(
            f"Processing analyzer {display_name} ({internal_name}): {len(vulns)} vulnerabilities"
        )

        if vulns:
            # Extract threat names and severities
            threat_names = []
            severities = []

            for vuln in vulns:
                severities.append(vuln.severity)
                logger.debug(
                    f"Processing vulnerability: {vuln.summary}, severity: {vuln.severity}"
                )

                # Extract threat name from details
                if (
                    hasattr(vuln, "details")
                    and vuln.details
                    and "threat_type" in vuln.details
                ):
                    threat_type = vuln.details["threat_type"]
                    if threat_type not in threat_names:
                        threat_names.append(threat_type)

            # Get the highest severity for this analyzer
            analyzer_severity = get_highest_severity(severities)
            logger.debug(
                f"Analyzer {display_name} severity: {analyzer_severity}, threat names: {threat_names}"
            )

            highest_severity = analyzer_severity

            # Generate threat summary - handle UNKNOWN threats specially
            if analyzer_severity == "UNKNOWN":
                threat_summary = "Analysis failed - status unknown"
                if len(threat_names) == 0 or (
                    len(threat_names) == 1 and threat_names[0].lower() == "unknown"
                ):
                    threat_names = ["UNKNOWN"]
            elif len(threat_names) == 0:
                threat_summary = "No specific threats identified"
            elif len(threat_names) == 1:
                threat_summary = (
                    f"Detected 1 threat: {threat_names[0].lower().replace('_', ' ')}"
                )
            else:
                threat_summary = f"Detected {len(threat_names)} threats: {', '.join([t.lower().replace('_', ' ') for t in threat_names])}"
        else:
            # If the analyzer was run but found nothing, it's SAFE.
            # We check if the internal name is in the list of analyzers that were part of the scan.
            ran_analyzers = [f for f in scanner_result.analyzers]
            logger.debug(
                f"Scanner Result {scanner_result.tool_name} findings: {scanner_result.findings}"
            )
            logger.debug(
                f"Ran Analyzers: {ran_analyzers} Internal Name: {internal_name}"
            )

            # Handle both enum analyzers and custom analyzers
            ran_analyzer_values = []
            for a in ran_analyzers:
                if hasattr(a, "value"):  # AnalyzerEnum objects
                    ran_analyzer_values.append(a.value)
                else:  # Custom analyzer names (strings)
                    ran_analyzer_values.append(str(a))

            # Check if this analyzer was run
            if internal_name in default_analyzers.values():  # Built-in analyzer
                expected_value = (
                    internal_name.lower()
                )  # "API" -> "api", "YARA" -> "yara", etc.
                analyzer_was_run = expected_value in ran_analyzer_values
            else:  # Custom analyzer
                analyzer_was_run = internal_name in ran_analyzer_values

            if analyzer_was_run:
                highest_severity = "SAFE"
                threat_summary = "No threats detected"
            else:
                highest_severity = "UNKNOWN"
                threat_summary = "Analyzer not run"
            threat_names = []

        grouped_findings[display_name] = {
            "severity": highest_severity,
            "threat_names": threat_names,
            "threat_summary": threat_summary,
            "total_findings": len(vulns),
        }

    return ToolScanResult(
        tool_name=scanner_result.tool_name,
        status=scanner_result.status,
        findings=grouped_findings,
        is_safe=scanner_result.is_safe,
    )


def _format_scan_results(
    results: List[ScanResult],
    output_format: OutputFormat,
    severity_filter: SeverityFilter = SeverityFilter.ALL,
    analyzer_filter: Optional[str] = None,
    tool_filter: Optional[str] = None,
    hide_safe: bool = False,
    show_stats: bool = False,
) -> Union[str, dict, List[dict]]:
    """Format scan results using ReportGenerator."""
    # Create ReportGenerator instance - convert scan results to expected format
    scan_data = process_scan_results(results)
    generator = ReportGenerator(scan_data)

    # Generate formatted output (no mapping needed - using unified enums)
    formatted_output = generator.format_output(
        format_type=output_format,
        tool_filter=tool_filter,
        analyzer_filter=analyzer_filter,
        severity_filter=severity_filter,
        show_safe=not hide_safe,
    )

    # Add statistics if requested
    if show_stats:
        stats = generator.get_statistics()
        if isinstance(formatted_output, str):
            formatted_output += f"\n\nStatistics: {stats}"
        elif isinstance(formatted_output, dict):
            formatted_output["statistics"] = stats
        elif isinstance(formatted_output, list):
            formatted_output = {"results": formatted_output, "statistics": stats}

    return formatted_output


@router.post(
    "/scan-tool",
    response_model=Union[ToolScanResult, FormattedScanResponse],
    tags=["Scanning"],
)
async def scan_tool_endpoint(
    request: SpecificToolScanRequest,
    http_request: Request,
    scanner_factory: ScannerFactory = Depends(get_scanner),
):
    """Scan a specific tool on an MCP server."""
    logger.debug(
        f"Starting tool scan - server: {request.server_url}, tool: {request.tool_name}"
    )

    try:
        scanner = scanner_factory(request.analyzers)

        # Extract HTTP headers for analyzers
        http_headers = dict(http_request.headers)

        result = await scanner.scan_remote_server_tool(
            server_url=request.server_url,
            tool_name=request.tool_name,
            analyzers=request.analyzers,
            http_headers=http_headers,
        )
        # Only warn if analyzers actually failed to run
        if len(result.findings) == 0 and len(result.analyzers) == 0:
            logger.warning(
                f"No analyzers ran for tool '{request.tool_name}' - check analyzer configuration"
            )

        api_result = _convert_scanner_result_to_api_result(result, scanner)

        if request.output_format == OutputFormat.RAW:
            logger.debug("Returning raw API result")
            return api_result

        formatted_output = _format_scan_results(
            results=[result],
            output_format=request.output_format,
            severity_filter=request.severity_filter,
            analyzer_filter=request.analyzer_filter,
            tool_filter=request.tool_filter,
            hide_safe=request.hide_safe,
            show_stats=request.show_stats,
        )

        response = FormattedScanResponse(
            server_url=request.server_url,
            output_format=request.output_format.value,
            formatted_output=formatted_output,
            raw_results=(
                [api_result] if request.output_format != OutputFormat.RAW else None
            ),
        )
        logger.debug(f"Tool scan completed successfully for {request.tool_name}")
        return response

    except ValueError as e:
        logger.error(f"ValueError in tool scan: {str(e)}")
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Unexpected error in tool scan: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error scanning tool: {str(e)}")


@router.post(
    "/scan-all-tools",
    response_model=Union[AllToolsScanResponse, FormattedScanResponse],
    tags=["Scanning"],
)
async def scan_all_tools_endpoint(
    request: APIScanRequest,
    http_request: Request,
    scanner_factory: ScannerFactory = Depends(get_scanner),
):
    """Scan all tools on an MCP server."""
    logger.debug(f"Starting full server scan - server: {request.server_url}")

    try:
        scanner = scanner_factory(request.analyzers)

        # Extract HTTP headers for analyzers
        http_headers = dict(http_request.headers)

        results = await scanner.scan_remote_server_tools(
            server_url=request.server_url,
            analyzers=request.analyzers,
            http_headers=http_headers,
        )
        logger.debug(f"Scanner completed - scanned {len(results)} tools")

        api_results = [
            _convert_scanner_result_to_api_result(res, scanner) for res in results
        ]

        if request.output_format == OutputFormat.RAW:
            logger.debug("Returning raw API results")
            return AllToolsScanResponse(
                server_url=request.server_url, scan_results=api_results
            )

        formatted_output = _format_scan_results(
            results=results,
            output_format=request.output_format,
            severity_filter=request.severity_filter,
            analyzer_filter=request.analyzer_filter,
            tool_filter=request.tool_filter,
            hide_safe=request.hide_safe,
            show_stats=request.show_stats,
        )

        response = FormattedScanResponse(
            server_url=request.server_url,
            output_format=request.output_format.value,
            formatted_output=formatted_output,
            raw_results=(
                api_results if request.output_format != OutputFormat.RAW else None
            ),
        )

        logger.debug(
            f"Full server scan completed successfully - {len(results)} tools processed"
        )

        return response

    except ValueError as e:
        logger.error(f"ValueError in full server scan: {str(e)}")
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Unexpected error in full server scan: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error scanning tools: {str(e)}")
