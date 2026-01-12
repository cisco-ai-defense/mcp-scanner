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

from typing import Any, Dict, List, Optional, Union

from fastapi import APIRouter, Depends, HTTPException, Request

from ..core.auth import Auth
from ..core.models import (
    AllToolsScanResponse,
    APIScanRequest,
    FormattedToolScanResponse,
    OutputFormat,
    SeverityFilter,
    SpecificToolScanRequest,
    SpecificPromptScanRequest,
    SpecificResourceScanRequest,
    SpecificInstructionsScanRequest,
    ToolScanResult,
)
from ..core.report_generator import ReportGenerator, results_to_json
from ..core.result import (
    ScanResult,
    PromptScanResult,
    ResourceScanResult,
    InstructionsScanResult,
    get_highest_severity,
    group_findings_by_analyzer,
)
from ..core.scanner import Scanner, ScannerFactory
from ..utils.logging_config import get_logger
from ..core.auth import AuthType
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


def _build_taxonomy_hierarchy(findings: List[Any]) -> List[Dict[str, Any]]:
    """
    Build hierarchical MCP Taxonomy structure from findings.
    
    Groups findings by technique -> sub-technique and returns a nested structure.
    
    Args:
        findings: List of SecurityFinding objects
        
    Returns:
        List of technique dictionaries with nested sub-techniques and findings
    """
    from collections import defaultdict
    
    # Group findings by technique and sub-technique
    technique_map = defaultdict(lambda: defaultdict(list))
    
    for finding in findings:
        if not hasattr(finding, 'mcp_taxonomy') or not finding.mcp_taxonomy:
            continue
            
        taxonomy = finding.mcp_taxonomy
        aitech = taxonomy.get('aitech')
        aitech_name = taxonomy.get('aitech_name')
        aisubtech = taxonomy.get('aisubtech')
        aisubtech_name = taxonomy.get('aisubtech_name')
        
        if not aitech:
            continue
            
        # Create technique key
        tech_key = (aitech, aitech_name)
        
        # Create sub-technique key (use "N/A" if no sub-technique)
        subtech_key = (aisubtech or "N/A", aisubtech_name or "N/A")
        
        # Add finding to the appropriate group
        technique_map[tech_key][subtech_key].append(finding)
    
    # Build the hierarchical structure
    result = []
    
    for (tech_id, tech_name), subtechs in technique_map.items():
        technique_dict = {
            "technique_id": tech_id,
            "technique_name": tech_name,
            "items": []
        }
        
        for (subtech_id, subtech_name), subtech_findings in subtechs.items():
            # Determine max severity for this sub-technique
            severities = [f.severity for f in subtech_findings]
            max_severity = get_highest_severity(severities)
            
            # Get description from the first finding (all findings in same sub-technique have same description)
            description = None
            if subtech_findings and hasattr(subtech_findings[0], 'mcp_taxonomy') and subtech_findings[0].mcp_taxonomy:
                description = subtech_findings[0].mcp_taxonomy.get('description')
            
            subtech_dict = {
                "sub_technique_id": subtech_id if subtech_id != "N/A" else None,
                "sub_technique_name": subtech_name if subtech_name != "N/A" else None,
                "max_severity": max_severity,
                "description": description,
            }
            
            technique_dict["items"].append(subtech_dict)
        
        result.append(technique_dict)
    
    return result


def _group_findings_for_api(
    scanner_result: Union[ToolScanResult, PromptScanResult, ResourceScanResult, InstructionsScanResult],
    scanner: Scanner
) -> Dict[str, Any]:
    """
    Extract and group findings by analyzer for API response.

    This helper function processes findings from any scan result type and returns
    a dictionary of grouped findings suitable for API responses.

    Args:
        scanner_result: The scan result (tool, prompt, or resource)
        scanner: The scanner instance

    Returns:
        Dict with analyzer findings grouped by analyzer name
    """
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
            f"Processing analyzer {display_name} ({internal_name}): {len(vulns)} security findings"
        )

        if vulns:
            # Extract threat names and severities
            threat_names = []
            severities = []

            for vuln in vulns:
                severities.append(vuln.severity)
                logger.debug(
                    f"Processing security finding: {vuln.summary}, severity: {vuln.severity}"
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

            # Get result identifier based on type for logging
            if isinstance(scanner_result, ToolScanResult):
                result_id = scanner_result.tool_name
            elif isinstance(scanner_result, PromptScanResult):
                result_id = scanner_result.prompt_name
            elif isinstance(scanner_result, ResourceScanResult):
                result_id = scanner_result.resource_uri
            elif isinstance(scanner_result, InstructionsScanResult):
                result_id = f"instructions:{scanner_result.server_name}"
            else:
                result_id = "unknown"

            logger.debug(
                f"Scanner Result {result_id} findings: {scanner_result.findings}"
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

        # Build the base structure (simplified - removed threat_names and threat_summary)
        analyzer_result = {
            "severity": highest_severity,
            "total_findings": len(vulns),
        }
        
        # Add MCP Taxonomy hierarchy if there are findings
        if vulns:
            threats_hierarchy = _build_taxonomy_hierarchy(vulns)
            if threats_hierarchy:
                analyzer_result["threats"] = {
                    "items": threats_hierarchy
                }
        
        grouped_findings[display_name] = analyzer_result

    return grouped_findings


def _convert_scanner_result_to_tool_api_result(
    scanner_result: ScanResult, scanner: Scanner
) -> ToolScanResult:
    """Convert a scanner result to a tool API result with grouped analyzer findings."""
    grouped_findings = _group_findings_for_api(scanner_result, scanner)

    return ToolScanResult(
        tool_name=scanner_result.tool_name,
        status=scanner_result.status,
        findings=grouped_findings,
        is_safe=scanner_result.is_safe,
    )


async def _format_tool_scan_results(
    results: List[ScanResult],
    output_format: OutputFormat,
    server_url: str = "Unknown",
    severity_filter: SeverityFilter = SeverityFilter.ALL,
    analyzer_filter: Optional[str] = None,
    tool_filter: Optional[str] = None,
    hide_safe: bool = False,
    show_stats: bool = False,
) -> Union[str, dict, List[dict]]:
    """Format scan results using ReportGenerator."""
    # Convert ScanResult objects to JSON format
    json_results = await results_to_json(results)
    
    # Create ReportGenerator instance with proper structure
    scan_data = {
        "server_url": server_url,
        "scan_results": json_results,
    }
    
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
    response_model=Union[ToolScanResult, FormattedToolScanResponse],
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


        auth = None
        if request.auth:
            if request.auth.auth_type == AuthType.BEARER:
                auth = Auth.bearer(request.auth.bearer_token)
                if request.auth.custom_headers:
                    auth.custom_headers = request.auth.custom_headers
            elif request.auth.auth_type == AuthType.APIKEY:
                auth = Auth.apikey(request.auth.api_key, request.auth.api_key_header)
                if request.auth.custom_headers:
                    auth.custom_headers = request.auth.custom_headers
            elif request.auth.custom_headers:
                # Custom headers only (no bearer or API key)
                auth = Auth.custom(request.auth.custom_headers)

        result = await scanner.scan_remote_server_tool(
            server_url=request.server_url,
            tool_name=request.tool_name,
            auth=auth,
            analyzers=request.analyzers,
            http_headers=http_headers,
        )
        # Only warn if analyzers actually failed to run
        if len(result.findings) == 0 and len(result.analyzers) == 0:
            logger.warning(
                f"No analyzers ran for tool '{request.tool_name}' - check analyzer configuration"
            )

        api_result = _convert_scanner_result_to_tool_api_result(result, scanner)

        if request.output_format == OutputFormat.RAW:
            logger.debug("Returning raw API result")
            return api_result

        formatted_output = await _format_tool_scan_results(
            results=[result],
            output_format=request.output_format,
            server_url=request.server_url,
            severity_filter=request.severity_filter,
            analyzer_filter=request.analyzer_filter,
            tool_filter=request.tool_filter,
            hide_safe=request.hide_safe,
            show_stats=request.show_stats,
        )

        response = FormattedToolScanResponse(
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
    response_model=Union[AllToolsScanResponse, FormattedToolScanResponse],
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

        auth = None
        if request.auth:
            if request.auth.auth_type == AuthType.BEARER:
                auth = Auth.bearer(request.auth.bearer_token)
                if request.auth.custom_headers:
                    auth.custom_headers = request.auth.custom_headers
            elif request.auth.auth_type == AuthType.APIKEY:
                auth = Auth.apikey(request.auth.api_key, request.auth.api_key_header)
                if request.auth.custom_headers:
                    auth.custom_headers = request.auth.custom_headers
            elif request.auth.custom_headers:
                auth = Auth.custom(request.auth.custom_headers)

        results = await scanner.scan_remote_server_tools(
            server_url=request.server_url,
            auth=auth,
            analyzers=request.analyzers,
            http_headers=http_headers,
        )
        logger.debug(f"Scanner completed - scanned {len(results)} tools")

        api_results = [
            _convert_scanner_result_to_tool_api_result(res, scanner) for res in results
        ]

        if request.output_format == OutputFormat.RAW:
            logger.debug("Returning raw API results")
            return AllToolsScanResponse(
                server_url=request.server_url, scan_results=api_results
            )

        formatted_output = await _format_tool_scan_results(
            results=results,
            output_format=request.output_format,
            server_url=request.server_url,
            severity_filter=request.severity_filter,
            analyzer_filter=request.analyzer_filter,
            tool_filter=request.tool_filter,
            hide_safe=request.hide_safe,
            show_stats=request.show_stats,
        )

        response = FormattedToolScanResponse(
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


@router.post(
    "/scan-prompt",
    response_model=dict,
    tags=["Scanning"],
)
async def scan_prompt_endpoint(
    request: SpecificPromptScanRequest,
    http_request: Request,
    scanner_factory: ScannerFactory = Depends(get_scanner),
):
    """Scan a specific prompt on an MCP server."""
    logger.debug(f"Starting specific prompt scan - server: {request.server_url}, prompt: {request.prompt_name}")

    try:
        scanner = scanner_factory(request.analyzers)

        # Extract HTTP headers for analyzers
        http_headers = dict(http_request.headers)

        auth = None
        if request.auth:
            if request.auth.auth_type == AuthType.BEARER:
                auth = Auth.bearer(request.auth.bearer_token)
                if request.auth.custom_headers:
                    auth.custom_headers = request.auth.custom_headers
            elif request.auth.auth_type == AuthType.APIKEY:
                auth = Auth.apikey(request.auth.api_key, request.auth.api_key_header)
                if request.auth.custom_headers:
                    auth.custom_headers = request.auth.custom_headers
            elif request.auth.custom_headers:
                auth = Auth.custom(request.auth.custom_headers)

        result = await scanner.scan_remote_server_prompt(
            server_url=request.server_url,
            prompt_name=request.prompt_name,
            auth=auth,
            analyzers=request.analyzers,
            http_headers=http_headers,
        )
        logger.debug(f"Scanner completed - scanned prompt: {request.prompt_name}")

        # Convert result to API format using helper function
        grouped_findings = _group_findings_for_api(result, scanner)

        response = {
            "server_url": request.server_url,
            "prompt_name": result.prompt_name,
            "prompt_description": result.prompt_description,
            "status": result.status,
            "is_safe": result.is_safe,
            "findings": grouped_findings,
        }

        logger.debug(f"Prompt scan completed successfully for {request.prompt_name}")
        return response

    except ValueError as e:
        logger.error(f"ValueError in prompt scan: {str(e)}")
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Unexpected error in prompt scan: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error scanning prompt: {str(e)}")


@router.post(
    "/scan-all-prompts",
    response_model=dict,
    tags=["Scanning"],
)
async def scan_all_prompts_endpoint(
    request: APIScanRequest,
    http_request: Request,
    scanner_factory: ScannerFactory = Depends(get_scanner),
):
    """Scan all prompts on an MCP server."""
    logger.debug(f"Starting all prompts scan - server: {request.server_url}")

    try:
        scanner = scanner_factory(request.analyzers)

        # Extract HTTP headers for analyzers
        http_headers = dict(http_request.headers)

        auth = None
        if request.auth:
            if request.auth.auth_type == AuthType.BEARER:
                auth = Auth.bearer(request.auth.bearer_token)
                if request.auth.custom_headers:
                    auth.custom_headers = request.auth.custom_headers
            elif request.auth.auth_type == AuthType.APIKEY:
                auth = Auth.apikey(request.auth.api_key, request.auth.api_key_header)
                if request.auth.custom_headers:
                    auth.custom_headers = request.auth.custom_headers
            elif request.auth.custom_headers:
                auth = Auth.custom(request.auth.custom_headers)

        results = await scanner.scan_remote_server_prompts(
            server_url=request.server_url,
            auth=auth,
            analyzers=request.analyzers,
            http_headers=http_headers,
        )
        logger.debug(f"Scanner completed - scanned {len(results)} prompts")

        # Convert results to API format
        prompt_results = []
        for result in results:
            # Use helper function to group findings
            grouped_findings = _group_findings_for_api(result, scanner)

            prompt_results.append({
                "prompt_name": result.prompt_name,
                "prompt_description": result.prompt_description,
                "status": result.status,
                "is_safe": result.is_safe,
                "findings": grouped_findings,
            })

        response = {
            "server_url": request.server_url,
            "total_prompts": len(results),
            "safe_prompts": sum(1 for r in results if r.is_safe),
            "unsafe_prompts": sum(1 for r in results if not r.is_safe),
            "prompts": prompt_results,
        }

        logger.debug(f"Prompt scan completed successfully - {len(results)} prompts processed")
        return response

    except ValueError as e:
        logger.error(f"ValueError in prompt scan: {str(e)}")
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Unexpected error in prompt scan: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error scanning prompts: {str(e)}")


@router.post(
    "/scan-resource",
    response_model=dict,
    tags=["Scanning"],
)
async def scan_resource_endpoint(
    request: SpecificResourceScanRequest,
    http_request: Request,
    scanner_factory: ScannerFactory = Depends(get_scanner),
):
    """Scan a specific resource on an MCP server."""
    logger.debug(f"Starting specific resource scan - server: {request.server_url}, resource: {request.resource_uri}")

    try:
        scanner = scanner_factory(request.analyzers)

        # Extract HTTP headers for analyzers
        http_headers = dict(http_request.headers)

        auth = None
        if request.auth:
            if request.auth.auth_type == AuthType.BEARER:
                auth = Auth.bearer(request.auth.bearer_token)
                if request.auth.custom_headers:
                    auth.custom_headers = request.auth.custom_headers
            elif request.auth.auth_type == AuthType.APIKEY:
                auth = Auth.apikey(request.auth.api_key, request.auth.api_key_header)
                if request.auth.custom_headers:
                    auth.custom_headers = request.auth.custom_headers
            elif request.auth.custom_headers:
                auth = Auth.custom(request.auth.custom_headers)

        # Use allowed MIME types from request or default
        allowed_mime_types = request.allowed_mime_types or ["text/plain", "text/html"]

        result = await scanner.scan_remote_server_resource(
            server_url=request.server_url,
            resource_uri=request.resource_uri,
            auth=auth,
            analyzers=request.analyzers,
            http_headers=http_headers,
            allowed_mime_types=allowed_mime_types,
        )
        logger.debug(f"Scanner completed - scanned resource: {request.resource_uri}")

        # Convert result to API format using helper function
        if result.status == "completed":
            grouped_findings = _group_findings_for_api(result, scanner)
        else:
            grouped_findings = {}

        response = {
            "server_url": request.server_url,
            "resource_uri": result.resource_uri,
            "resource_name": result.resource_name,
            "resource_mime_type": result.resource_mime_type,
            "status": result.status,
            "is_safe": result.is_safe if result.status == "completed" else None,
            "findings": grouped_findings,
        }

        logger.debug(f"Resource scan completed successfully for {request.resource_uri}")
        return response

    except ValueError as e:
        logger.error(f"ValueError in resource scan: {str(e)}")
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Unexpected error in resource scan: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error scanning resource: {str(e)}")


@router.post(
    "/scan-all-resources",
    response_model=dict,
    tags=["Scanning"],
)
async def scan_all_resources_endpoint(
    request: APIScanRequest,
    http_request: Request,
    scanner_factory: ScannerFactory = Depends(get_scanner),
):
    """Scan all resources on an MCP server."""
    logger.debug(f"Starting all resources scan - server: {request.server_url}")

    try:
        scanner = scanner_factory(request.analyzers)

        # Extract HTTP headers for analyzers
        http_headers = dict(http_request.headers)

        auth = None
        if request.auth:
            if request.auth.auth_type == AuthType.BEARER:
                auth = Auth.bearer(request.auth.bearer_token)
                if request.auth.custom_headers:
                    auth.custom_headers = request.auth.custom_headers
            elif request.auth.auth_type == AuthType.APIKEY:
                auth = Auth.apikey(request.auth.api_key, request.auth.api_key_header)
                if request.auth.custom_headers:
                    auth.custom_headers = request.auth.custom_headers
            elif request.auth.custom_headers:
                auth = Auth.custom(request.auth.custom_headers)

        # Default allowed MIME types
        allowed_mime_types = ["text/plain", "text/html"]

        results = await scanner.scan_remote_server_resources(
            server_url=request.server_url,
            auth=auth,
            analyzers=request.analyzers,
            http_headers=http_headers,
            allowed_mime_types=allowed_mime_types,
        )
        logger.debug(f"Scanner completed - scanned {len(results)} resources")

        # Convert results to API format
        resource_results = []
        for result in results:
            if result.status == "completed":
                # Use helper function to group findings
                grouped_findings = _group_findings_for_api(result, scanner)

                resource_results.append({
                    "resource_uri": result.resource_uri,
                    "resource_name": result.resource_name,
                    "resource_mime_type": result.resource_mime_type,
                    "status": result.status,
                    "is_safe": result.is_safe,
                    "findings": grouped_findings,
                })
            else:
                # Skipped or failed resources
                resource_results.append({
                    "resource_uri": result.resource_uri,
                    "resource_name": result.resource_name,
                    "resource_mime_type": result.resource_mime_type,
                    "status": result.status,
                    "is_safe": None,
                    "findings": {},
                })

        completed = [r for r in results if r.status == "completed"]
        response = {
            "server_url": request.server_url,
            "total_resources": len(results),
            "scanned_resources": len(completed),
            "skipped_resources": sum(1 for r in results if r.status == "skipped"),
            "failed_resources": sum(1 for r in results if r.status == "failed"),
            "safe_resources": sum(1 for r in completed if r.is_safe),
            "unsafe_resources": sum(1 for r in completed if not r.is_safe),
            "allowed_mime_types": allowed_mime_types,
            "resources": resource_results,
        }

        logger.debug(f"Resource scan completed successfully - {len(results)} resources processed")
        return response

    except ValueError as e:
        logger.error(f"ValueError in resource scan: {str(e)}")
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Unexpected error in resource scan: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error scanning resources: {str(e)}")


@router.post(
    "/scan-instructions",
    response_model=dict,
    tags=["Scanning"],
)
async def scan_instructions_endpoint(
    request: SpecificInstructionsScanRequest,
    http_request: Request,
    scanner_factory: ScannerFactory = Depends(get_scanner),
):
    """Scan server instructions from the InitializeResult."""
    logger.debug(f"Starting instructions scan - server: {request.server_url}")

    try:
        scanner = scanner_factory(request.analyzers)

        # Extract HTTP headers for analyzers
        http_headers = dict(http_request.headers)

        auth = None
        if request.auth:
            if request.auth.auth_type == AuthType.BEARER:
                auth = Auth.bearer(request.auth.bearer_token)
            if request.auth.auth_type == AuthType.APIKEY:
                auth = Auth.apikey(request.auth.api_key, request.auth.api_key_header)

        result = await scanner.scan_remote_server_instructions(
            server_url=request.server_url,
            auth=auth,
            analyzers=request.analyzers,
            http_headers=http_headers,
        )
        logger.debug(f"Scanner completed - scanned instructions from server")

        # Convert result to API format using helper function
        if result.status == "completed":
            grouped_findings = _group_findings_for_api(result, scanner)
        else:
            grouped_findings = {}

        response = {
            "server_url": request.server_url,
            "server_name": result.server_name,
            "protocol_version": result.protocol_version,
            "instructions": result.instructions,
            "status": result.status,
            "is_safe": result.is_safe if result.status == "completed" else None,
            "findings": grouped_findings,
        }

        logger.debug(f"Instructions scan completed successfully")
        return response

    except ValueError as e:
        logger.error(f"ValueError in instructions scan: {str(e)}")
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Unexpected error in instructions scan: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error scanning instructions: {str(e)}")
