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
Pydantic models for MCP Scanner SDK.

This module contains Pydantic models for consistent data validation
and structure throughout the codebase.
"""

from enum import Enum
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field, field_validator
from .auth import APIAuthConfig, AuthType

class OutputFormat(str, Enum):
    """Available output formats."""

    RAW = "raw"
    SUMMARY = "summary"
    DETAILED = "detailed"
    BY_TOOL = "by_tool"
    BY_ANALYZER = "by_analyzer"
    BY_SEVERITY = "by_severity"
    TABLE = "table"


class SeverityFilter(str, Enum):
    """Available severity filters."""

    ALL = "all"
    HIGH = "high"
    UNKNOWN = "unknown"
    MEDIUM = "medium"
    LOW = "low"
    SAFE = "safe"


class AnalyzerEnum(str, Enum):
    """Available analyzers."""

    API = "api"
    YARA = "yara"
    LLM = "llm"
    BEHAVIORAL = "behavioral"


class AnalysisContext(BaseModel):
    """Context information for analysis operations."""

    tool_name: Optional[str] = Field(
        None, description="Name of the tool being analyzed"
    )
    content_type: Optional[str] = Field(
        None, description="Type of content being analyzed"
    )
    server_url: Optional[str] = Field(None, description="URL of the MCP server")
    additional_data: Dict[str, Any] = Field(
        default_factory=dict, description="Additional context data"
    )

    @field_validator("server_url")
    @classmethod
    def validate_server_url(cls, v):
        """Validate server URL format."""
        if v and not (v.startswith("http://") or v.startswith("https://")):
            raise ValueError("Server URL must start with http:// or https://")
        return v


class SecurityFindingDetails(BaseModel):
    """Detailed information about a security finding."""

    risk_score: Optional[float] = Field(
        None, ge=0, le=100, description="Risk score from 0-100"
    )
    threat_type: Optional[str] = Field(None, description="Type of threat detected")
    confidence: Optional[float] = Field(
        None, ge=0, le=1, description="Confidence level 0-1"
    )
    mitigation: Optional[str] = Field(None, description="Suggested mitigation")
    references: List[str] = Field(
        default_factory=list, description="Reference URLs or documentation"
    )
    affected_components: List[str] = Field(
        default_factory=list, description="Components affected by security finding"
    )

    @field_validator("risk_score")
    @classmethod
    def validate_risk_score(cls, v):
        """Validate risk score is within valid range."""
        if v is not None and (v < 0 or v > 100):
            raise ValueError("Risk score must be between 0 and 100")
        return v


class ScanConfiguration(BaseModel):
    """Configuration for scan operations."""

    api_scan: bool = Field(True, description="Enable API-based scanning")
    yara_scan: bool = Field(True, description="Enable YARA pattern scanning")
    llm_scan: bool = Field(True, description="Enable LLM AI scanning")
    timeout_seconds: float = Field(
        30.0, gt=0, description="Timeout for scan operations"
    )
    max_content_size: int = Field(
        100000, gt=0, description="Maximum content size to analyze"
    )

    @field_validator("timeout_seconds")
    @classmethod
    def validate_timeout(cls, v):
        """Validate timeout is reasonable."""
        if v <= 0:
            raise ValueError("Timeout must be positive")
        if v > 300:  # 5 minutes
            raise ValueError("Timeout cannot exceed 300 seconds")
        return v


class ToolMetadata(BaseModel):
    """Metadata about an MCP tool."""

    name: str = Field(..., description="Tool name")
    description: str = Field(..., description="Tool description")
    input_schema: Optional[Dict[str, Any]] = Field(
        None, description="Input schema definition"
    )
    server_url: Optional[str] = Field(
        None, description="Server URL where tool is hosted"
    )
    version: Optional[str] = Field(None, description="Tool version")

    @field_validator("name")
    @classmethod
    def validate_name(cls, v):
        """Validate tool name is not empty."""
        if not v or not v.strip():
            raise ValueError("Tool name cannot be empty")
        return v.strip()

    @field_validator("description")
    @classmethod
    def validate_description(cls, v):
        """Validate tool description is not empty."""
        if not v or not v.strip():
            raise ValueError("Tool description cannot be empty")
        return v.strip()


class ScanRequest(BaseModel):
    """Request model for scan operations."""

    server_url: str = Field(..., description="URL of the MCP server to scan")
    tool_name: Optional[str] = Field(
        None, description="Specific tool to scan (if None, scan all)"
    )
    config: ScanConfiguration = Field(
        default_factory=ScanConfiguration, description="Scan configuration"
    )
    context: AnalysisContext = Field(
        default_factory=AnalysisContext, description="Analysis context"
    )

    @field_validator("server_url")
    @classmethod
    def validate_server_url(cls, v):
        """Validate server URL format."""
        if not v or not v.strip():
            raise ValueError("Server URL cannot be empty")
        v = v.strip()
        if not (v.startswith("http://") or v.startswith("https://")):
            raise ValueError("Server URL must start with http:// or https://")
        return v


class AnalyzerResult(BaseModel):
    """Result from an individual analyzer."""

    analyzer_name: str = Field(..., description="Name of the analyzer")
    findings_found: int = Field(
        0, ge=0, description="Number of security findings found"
    )
    execution_time_ms: float = Field(
        0, ge=0, description="Execution time in milliseconds"
    )
    success: bool = Field(True, description="Whether analysis completed successfully")
    error_message: Optional[str] = Field(
        None, description="Error message if analysis failed"
    )

    @field_validator("analyzer_name")
    @classmethod
    def validate_analyzer_name(cls, v):
        """Validate analyzer name is not empty."""
        if not v or not v.strip():
            raise ValueError("Analyzer name cannot be empty")
        return v.strip()


class ScanSummary(BaseModel):
    """Summary of scan results."""

    total_tools_scanned: int = Field(
        0, ge=0, description="Total number of tools scanned"
    )
    total_findings: int = Field(
        0, ge=0, description="Total security findings found"
    )
    high_severity_count: int = Field(
        0, ge=0, description="Number of high severity security findings"
    )
    medium_severity_count: int = Field(
        0, ge=0, description="Number of medium severity security findings"
    )
    low_severity_count: int = Field(
        0, ge=0, description="Number of low severity security findings"
    )
    scan_duration_ms: float = Field(
        0, ge=0, description="Total scan duration in milliseconds"
    )
    analyzer_results: List[AnalyzerResult] = Field(
        default_factory=list, description="Results from individual analyzers"
    )

    @property
    def success_rate(self) -> float:
        """Calculate the success rate of analyzers."""
        if not self.analyzer_results:
            return 0.0
        successful = sum(1 for result in self.analyzer_results if result.success)
        return successful / len(self.analyzer_results)


class ErrorInfo(BaseModel):
    """Information about errors that occurred during scanning."""

    error_type: str = Field(..., description="Type of error")
    error_message: str = Field(..., description="Error message")
    component: Optional[str] = Field(None, description="Component where error occurred")
    timestamp: Optional[str] = Field(None, description="When the error occurred")
    context: Dict[str, Any] = Field(
        default_factory=dict, description="Additional error context"
    )

    @field_validator("error_type", "error_message")
    @classmethod
    def validate_not_empty(cls, v):
        """Validate required fields are not empty."""
        if not v or not v.strip():
            raise ValueError("Field cannot be empty")
        return v.strip()



class APIScanRequest(BaseModel):
    """Base request for scanning MCP servers via API."""

    server_url: str
    analyzers: List[AnalyzerEnum] = Field(
        default=[AnalyzerEnum.API, AnalyzerEnum.YARA, AnalyzerEnum.LLM],
        description="List of analyzers to run",
    )
    output_format: OutputFormat = OutputFormat.RAW
    severity_filter: SeverityFilter = SeverityFilter.ALL
    analyzer_filter: Optional[str] = None
    tool_filter: Optional[str] = None
    hide_safe: bool = False
    show_stats: bool = False
    rules_path: Optional[str] = None
    auth: Optional[APIAuthConfig] = None


class SpecificToolScanRequest(APIScanRequest):
    """Request for scanning a single, specific tool via API."""

    tool_name: str


class SpecificPromptScanRequest(APIScanRequest):
    """Request for scanning a single, specific prompt via API."""

    prompt_name: str


class SpecificResourceScanRequest(APIScanRequest):
    """Request for scanning a single, specific resource via API."""

    resource_uri: str
    allowed_mime_types: Optional[List[str]] = ["text/plain", "text/html"]


class SpecificInstructionsScanRequest(APIScanRequest):
    """Request for scanning server instructions via API."""

    pass  # No additional fields needed - scans the server's instructions field


class AnalyzerFinding(BaseModel):
    """Analyzer finding with grouped structure."""

    severity: str
    threat_names: List[str]
    total_findings: int


class ToolScanResult(BaseModel):
    """Scan result for a single tool with grouped analyzer findings."""

    tool_name: str
    status: str
    findings: dict  # Dictionary with analyzer names as keys
    is_safe: bool


class AllToolsScanResponse(BaseModel):
    """Scan response for all tools on a server."""

    server_url: str
    scan_results: List[ToolScanResult]


class FormattedToolScanResponse(BaseModel):
    """Formatted tool scan response with custom output format.

    This model is used for formatted responses from tool scans.
    """

    server_url: str
    output_format: str
    formatted_output: Union[str, dict, List[dict]]
    raw_results: Optional[List[ToolScanResult]] = None
