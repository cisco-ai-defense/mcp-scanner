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

from pydantic import BaseModel, Field, field_validator, model_validator

from ..utils.logging_config import get_logger

_models_logger = get_logger(__name__)
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
    VIRUSTOTAL = "virustotal"
    READINESS = "readiness"
    PROMPT_DEFENSE = "prompt_defense"
    VULNERABLE_PACKAGE = "vulnerable_package"
    META = "meta"


# Analyzers that are exposed via the FastAPI HTTP surface. The other
# analyzers (BEHAVIORAL, PROMPT_DEFENSE, VIRUSTOTAL, READINESS,
# VULNERABLE_PACKAGE) ship via the SDK / CLI only — they were producing
# findings the API response shape silently dropped (see _group_findings_for_api),
# so we reject them at the request boundary with a clear 422 instead of
# letting operators believe a scan ran.
API_ALLOWED_ANALYZERS: frozenset[AnalyzerEnum] = frozenset(
    {
        AnalyzerEnum.API,
        AnalyzerEnum.YARA,
        AnalyzerEnum.LLM,
        AnalyzerEnum.META,
    }
)


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
    total_findings: int = Field(0, ge=0, description="Total security findings found")
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
        description=(
            "List of analyzers to run. The HTTP API is restricted to "
            f"{sorted(a.value for a in API_ALLOWED_ANALYZERS)}. The remaining "
            "analyzers (behavioral, prompt_defense, virustotal, readiness, "
            "vulnerable_package) are SDK/CLI-only — requesting them via API "
            "returns 422."
        ),
    )
    enable_meta: bool = Field(
        default=False,
        description=(
            "Enable the second-pass LLM meta-analyzer for false-positive "
            "filtering. Mirrors the CLI --enable-meta flag.\n\n"
            "**Semantics (OR-merge with `analyzers`):** META runs if "
            "EITHER `enable_meta` is True OR `meta` appears in `analyzers`. "
            "This flag is purely additive — it never subtracts. Setting "
            "`enable_meta=False` while `meta` is already in `analyzers` "
            "does NOT disable META; remove `meta` from `analyzers` "
            "instead. The two forms are equivalent and the recommended "
            "spelling is `enable_meta=True` with META omitted from the "
            "list (it appears in OpenAPI as a discoverable boolean).\n\n"
            "Requires an LLM API key (or AWS credentials for Bedrock "
            "models)."
        ),
    )
    output_format: OutputFormat = OutputFormat.RAW
    severity_filter: SeverityFilter = SeverityFilter.ALL
    analyzer_filter: Optional[str] = None
    tool_filter: Optional[str] = None
    hide_safe: bool = False
    show_stats: bool = False
    rules_path: Optional[str] = None
    auth: Optional[APIAuthConfig] = None

    @field_validator("analyzers")
    @classmethod
    def _enforce_api_allowlist(
        cls, value: List[AnalyzerEnum]
    ) -> List[AnalyzerEnum]:
        """Reject analyzers that are not exposed over the HTTP surface.

        We validate at the request boundary rather than silently filtering
        because (a) the response shape used to drop findings from blocked
        analyzers without telling the caller, and (b) callers explicitly
        asking for behavioral/prompt_defense/virustotal/readiness/vulnerable_package
        almost certainly mean to use the SDK or CLI and need the loud error.
        """
        if not value:
            return value
        rejected = sorted(
            {a.value for a in value if a not in API_ALLOWED_ANALYZERS}
        )
        if rejected:
            allowed = sorted(a.value for a in API_ALLOWED_ANALYZERS)
            raise ValueError(
                f"Analyzers {rejected} are not available over the HTTP API. "
                f"Allowed: {allowed}. Use the CLI/SDK for the remaining analyzers."
            )
        return value

    @model_validator(mode="after")
    def _warn_on_meta_field_disagreement(self) -> "APIScanRequest":
        """P2-5: warn (don't reject) when ``enable_meta=False`` but
        ``meta`` is in ``analyzers``.

        ``enable_meta`` is OR-merged with the list — never subtractive
        — so this combination still runs META, which surprises callers
        who read ``enable_meta=False`` as a kill-switch. We emit a
        WARNING so the inconsistency shows up in operator logs without
        breaking the existing pattern of explicitly listing META in
        ``analyzers`` (which predates the flag).
        """
        if (
            not self.enable_meta
            and AnalyzerEnum.META in self.analyzers
        ):
            _models_logger.warning(
                "APIScanRequest: enable_meta=False but 'meta' is in "
                "analyzers=%r — META will still run (the flag is "
                "additive, not subtractive). Either remove 'meta' "
                "from analyzers OR set enable_meta=True for clarity.",
                [a.value for a in self.analyzers],
            )
        return self

    def resolved_analyzers(self) -> List[AnalyzerEnum]:
        """Return the effective analyzer list with `enable_meta` applied.

        The CLI ``--enable-meta`` flag and an explicit ``meta`` entry in
        ``analyzers`` are equivalent. This helper keeps that contract in one
        place so every scan endpoint resolves the list the same way.

        Returns:
            List[AnalyzerEnum]: ``analyzers`` with ``META`` appended if
            ``enable_meta`` is True and ``META`` is not already present.
        """
        analyzers = list(self.analyzers)
        if self.enable_meta and AnalyzerEnum.META not in analyzers:
            analyzers.append(AnalyzerEnum.META)
        return analyzers


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


class MetaAnalysisAudit(BaseModel):
    """Audit trail for meta-analyzer false-positive filtering.

    Attached to a scan result whenever the meta-analyzer (``enable_meta=True``
    or ``analyzers=["...","meta"]``) judged at least one finding to be a
    false positive. Without this block, ``"is_safe": true`` cannot be
    distinguished between *clean tool* and *meta filtered everything to
    clean* — making this the only operator-visible signal that meta
    filtering changed the response.
    """

    filtered_count: int = Field(
        ...,
        description="Number of findings the meta-analyzer marked as false positives.",
    )
    filtered_findings: List[Dict[str, Any]] = Field(
        default_factory=list,
        description=(
            "Compact records of the dropped findings: ``analyzer``, ``severity``, "
            "``summary``, ``threat_category``, ``meta_reason`` (LLM-supplied "
            "rationale), and optional ``meta_confidence``."
        ),
    )


class ToolScanResult(BaseModel):
    """Scan result for a single tool with grouped analyzer findings."""

    tool_name: str
    status: str
    findings: dict  # Dictionary with analyzer names as keys
    is_safe: bool
    meta_analysis: Optional[MetaAnalysisAudit] = Field(
        default=None,
        description=(
            "Meta-analyzer audit trail. Present iff meta-analysis ran AND "
            "filtered at least one finding; otherwise omitted to keep the "
            "response shape backwards-compatible."
        ),
    )


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
