# Copyright 2026 Cisco Systems, Inc. and its affiliates
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

"""LLM Meta-Analyzer module for MCP Scanner.

This module contains the LLM Meta-Analyzer that performs second-pass analysis
on all findings from other analyzers. It helps prune false positives, prioritize
findings, correlate related issues, and provide actionable recommendations.

The meta-analyzer runs AFTER all other analyzers complete, reviewing their collective
findings to provide expert-level analysis and actionable recommendations.

Requirements:
    - Enable via CLI --enable-meta flag or API enable_meta parameter

Configuration:
    The meta-analyzer can use different LLM settings than the primary LLM analyzer:
    - MCP_SCANNER_META_LLM_API_KEY: API key for meta-analyzer
    - MCP_SCANNER_META_LLM_MODEL: Model for meta-analyzer
    - MCP_SCANNER_META_LLM_BASE_URL: Base URL for meta-analyzer
    - MCP_SCANNER_META_LLM_API_VERSION: API version for meta-analyzer
    
    If not set, these fall back to the primary LLM settings (MCP_SCANNER_LLM_*).
"""

import asyncio
import json
import os
import secrets
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from litellm import acompletion

from .base import BaseAnalyzer, SecurityFinding
from ...config.config import Config
from ...config.constants import MCPScannerConstants
from ...utils.logging_config import get_logger

logger = get_logger(__name__)


@dataclass
class MetaAnalysisResult:
    """Result of meta-analysis on security findings.
    
    Attributes:
        validated_findings: Findings confirmed as true positives with enriched data.
        false_positives: Findings identified as likely false positives.
        priority_order: Ordered list of finding indices by priority.
        correlations: Groups of related findings.
        recommendations: Actionable recommendations for remediation.
        overall_risk_assessment: Summary risk assessment.
    """
    validated_findings: List[Dict[str, Any]] = field(default_factory=list)
    false_positives: List[Dict[str, Any]] = field(default_factory=list)
    priority_order: List[int] = field(default_factory=list)
    correlations: List[Dict[str, Any]] = field(default_factory=list)
    recommendations: List[Dict[str, Any]] = field(default_factory=list)
    overall_risk_assessment: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        return {
            "validated_findings": self.validated_findings,
            "false_positives": self.false_positives,
            "priority_order": self.priority_order,
            "correlations": self.correlations,
            "recommendations": self.recommendations,
            "overall_risk_assessment": self.overall_risk_assessment,
            "summary": {
                "total_original": len(self.validated_findings) + len(self.false_positives),
                "validated_count": len(self.validated_findings),
                "false_positive_count": len(self.false_positives),
                "recommendations_count": len(self.recommendations),
            }
        }
    
    def get_validated_findings(self) -> List[SecurityFinding]:
        """Get validated findings as SecurityFinding objects.
        
        This is the primary output method - returns findings in the same
        format as other MCP Scanner analyzers (API, YARA, LLM, etc.).
        
        Returns:
            List[SecurityFinding]: Validated findings with meta-analysis enrichments.
        """
        findings = []
        for finding_data in self.validated_findings:
            # Build enriched details
            details = dict(finding_data.get("details", {}))
            
            # Add meta-analysis enrichments
            if "confidence" in finding_data:
                details["meta_confidence"] = finding_data["confidence"]
            if "confidence_reason" in finding_data:
                details["meta_confidence_reason"] = finding_data["confidence_reason"]
            if "exploitability" in finding_data:
                details["meta_exploitability"] = finding_data["exploitability"]
            if "impact" in finding_data:
                details["meta_impact"] = finding_data["impact"]
            if "enriched_details" in finding_data:
                details["meta_enriched"] = finding_data["enriched_details"]
            
            # Mark as meta-validated
            details["meta_validated"] = True
            
            finding = SecurityFinding(
                severity=finding_data.get("severity", "UNKNOWN"),
                summary=finding_data.get("summary", ""),
                threat_category=finding_data.get("threat_category", "Unknown"),
                analyzer=finding_data.get("analyzer", "META"),
                details=details,
            )
            findings.append(finding)
        return findings


class LLMMetaAnalyzer:
    """LLM-based meta-analyzer for reviewing and refining security findings.
    
    This analyzer performs a second-pass analysis on all findings from other
    analyzers to:
    - Prune false positives based on context
    - Prioritize findings by actual risk
    - Correlate related findings
    - Provide specific recommendations and fixes
    
    The meta-analyzer runs AFTER all other analyzers complete.
    Meta-analysis can run with any number of analyzers when enabled via CLI.
    """

    def __init__(
        self,
        config: Config,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        base_url: Optional[str] = None,
        api_version: Optional[str] = None,
    ):
        """Initialize the LLM Meta-Analyzer.
        
        Args:
            config: Configuration object with LLM settings.
            api_key: Override API key (defaults to config.meta_llm_api_key or llm_provider_api_key)
            model: Override model (defaults to config.meta_llm_model or llm_model)
            base_url: Override base URL (defaults to config.meta_llm_base_url or llm_base_url)
            api_version: Override API version (defaults to config.meta_llm_api_version or llm_api_version)
        """
        self.name = "META"
        self.config = config
        self.logger = get_logger(f"{__name__}.LLMMetaAnalyzer")

        # Use meta-specific settings with overrides, falling back to primary LLM settings
        self.api_key = (
            api_key 
            or os.environ.get("MCP_SCANNER_META_LLM_API_KEY")
            or config.llm_provider_api_key
        )
        self.model = (
            model 
            or os.environ.get("MCP_SCANNER_META_LLM_MODEL")
            or config.llm_model
        )
        self.base_url = (
            base_url 
            or os.environ.get("MCP_SCANNER_META_LLM_BASE_URL")
            or config.llm_base_url
        )
        self.api_version = (
            api_version 
            or os.environ.get("MCP_SCANNER_META_LLM_API_VERSION")
            or config.llm_api_version
        )

        # Check if Bedrock model (doesn't require API key)
        is_bedrock = self.model and "bedrock/" in self.model

        if not self.api_key and not is_bedrock:
            raise ValueError(
                "Meta-Analyzer LLM API key not configured. "
                "Set MCP_SCANNER_META_LLM_API_KEY or MCP_SCANNER_LLM_API_KEY environment variable."
            )

        # Validate Azure-specific configuration
        if self.model and self.model.startswith("azure/"):
            if not self.base_url:
                raise ValueError(
                    "Azure OpenAI base URL not configured for meta-analyzer. "
                    "Set MCP_SCANNER_META_LLM_BASE_URL or MCP_SCANNER_LLM_BASE_URL environment variable."
                )
            if not self.api_version:
                raise ValueError(
                    "Azure OpenAI API version not configured for meta-analyzer. "
                    "Set MCP_SCANNER_META_LLM_API_VERSION or MCP_SCANNER_LLM_API_VERSION environment variable."
                )

        # AWS Bedrock configuration
        self._aws_region = config.aws_region_name if is_bedrock else None
        self._aws_session_token = config.aws_session_token if is_bedrock else None
        self._aws_profile_name = config.aws_profile_name if is_bedrock else None

        # Load prompts from files
        self._load_prompts()
        
        self.logger.info(f"LLM Meta-Analyzer initialized with model: {self.model}")

    @staticmethod
    def should_run() -> bool:
        """Check if meta-analyzer should run.
        
        Meta-analyzer is controlled via CLI --enable-meta flag.
        No minimum analyzer count required.
            
        Returns:
            True - meta-analyzer can always run when enabled.
        """
        return True

    def _load_prompts(self):
        """Load prompt templates from files."""
        prompts_path = MCPScannerConstants.get_prompts_path()

        meta_analysis_file = prompts_path / "meta_analysis_prompt.md"
        try:
            self.system_prompt_template = meta_analysis_file.read_text(encoding="utf-8")
        except FileNotFoundError:
            self.logger.warning(
                f"Meta-analysis prompt file not found: {meta_analysis_file}"
            )
            self.system_prompt_template = self._get_default_system_prompt()

    def _get_default_system_prompt(self) -> str:
        """Get default system prompt if file not found."""
        return """You are a senior security analyst performing meta-analysis on security findings.
Your role is to review findings from multiple analyzers, identify false positives,
prioritize by actual risk, correlate related issues, and provide actionable recommendations.
Respond with JSON containing your analysis."""

    def _generate_random_delimiters(self) -> tuple:
        """Generate random delimiters for security.
        
        Returns:
            Tuple of (start_delimiter, end_delimiter)
        """
        random_id = secrets.token_hex(16)
        start_delimiter = f"<!---META_INPUT_START_{random_id}--->"
        end_delimiter = f"<!---META_INPUT_END_{random_id}--->"
        return start_delimiter, end_delimiter

    async def _make_llm_request(self, system_prompt: str, user_prompt: str) -> str:
        """Make a request to the LLM API using meta-analyzer specific settings.
        
        Args:
            system_prompt: System prompt for the LLM
            user_prompt: User prompt for the LLM
            
        Returns:
            LLM response text.
        """
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

        api_params = {
            "model": self.model,
            "messages": messages,
            "temperature": 0.1,
            "max_tokens": 8000,
            "timeout": 180.0,
        }

        if self.api_key:
            api_params["api_key"] = self.api_key

        if self.base_url:
            api_params["api_base"] = self.base_url

        if self.api_version:
            api_params["api_version"] = self.api_version

        # AWS Bedrock configuration
        if self._aws_region:
            api_params["aws_region_name"] = self._aws_region
        if self._aws_session_token:
            api_params["aws_session_token"] = self._aws_session_token
        if self._aws_profile_name:
            api_params["aws_profile_name"] = self._aws_profile_name

        # Retry logic with exponential backoff
        max_retries = 3
        last_exception = None

        for attempt in range(max_retries):
            try:
                self.logger.debug(f"LLM API attempt {attempt + 1}/{max_retries}")
                response = await acompletion(**api_params)
                return response.choices[0].message.content

            except Exception as e:
                last_exception = e
                error_msg = str(e).lower()

                is_retryable = any(
                    keyword in error_msg
                    for keyword in [
                        "timeout", "tls", "connection", "network",
                        "rate limit", "throttle", "429", "503", "504",
                    ]
                )

                if attempt < max_retries - 1 and is_retryable:
                    delay = (2 ** attempt) * 1.0
                    self.logger.warning(
                        f"LLM API request failed (attempt {attempt + 1}/{max_retries}): {e}"
                    )
                    self.logger.info(f"Retrying in {delay} seconds...")
                    await asyncio.sleep(delay)
                else:
                    self.logger.error(
                        f"LLM API request failed after {attempt + 1} attempts: {e}"
                    )
                    raise last_exception

    async def analyze_findings(
        self,
        findings: List[SecurityFinding],
        original_content: str,
        context: Optional[Dict[str, Any]] = None,
        analyzers_used: Optional[List[str]] = None,
    ) -> MetaAnalysisResult:
        """Perform meta-analysis on security findings.
        
        Args:
            findings: List of SecurityFinding objects from all analyzers
            original_content: The original scanned content for context
            context: Additional context about the scan
            analyzers_used: List of analyzer names that were used
            
        Returns:
            MetaAnalysisResult with validated findings, false positives, and recommendations
        """
        if not findings:
            self.logger.info("No findings to analyze")
            return MetaAnalysisResult(
                overall_risk_assessment={
                    "risk_level": "SAFE",
                    "summary": "No security findings to analyze",
                }
            )

        context = context or {}
        
        # Generate delimiters for security
        start_delimiter, end_delimiter = self._generate_random_delimiters()

        # Build prompts
        system_prompt = self.system_prompt_template
        user_prompt = self._build_user_prompt(
            findings, original_content, context, start_delimiter, end_delimiter, analyzers_used
        )

        try:
            response = await self._make_llm_request(system_prompt, user_prompt)
            result = self._parse_meta_response(response, findings)
            
            self.logger.info(
                f"Meta-analysis complete: {len(result.validated_findings)} validated, "
                f"{len(result.false_positives)} false positives, "
                f"{len(result.recommendations)} recommendations"
            )
            
            return result

        except Exception as e:
            self.logger.error(f"Meta-analysis failed: {e}")
            # Return original findings as validated if analysis fails
            return MetaAnalysisResult(
                validated_findings=[self._finding_to_dict(f) for f in findings],
                overall_risk_assessment={
                    "risk_level": "UNKNOWN",
                    "summary": f"Meta-analysis failed: {str(e)}",
                }
            )

    def _finding_to_dict(self, finding: SecurityFinding) -> Dict[str, Any]:
        """Convert SecurityFinding to dictionary format.
        
        Args:
            finding: SecurityFinding object
            
        Returns:
            Dictionary representation of the finding
        """
        return {
            "severity": finding.severity,
            "summary": finding.summary,
            "threat_category": finding.threat_category,
            "analyzer": finding.analyzer,
            "details": finding.details,
        }

    def _build_user_prompt(
        self,
        findings: List[SecurityFinding],
        original_content: str,
        context: Dict[str, Any],
        start_delimiter: str,
        end_delimiter: str,
        analyzers_used: Optional[List[str]] = None,
    ) -> str:
        """Build the user prompt for meta-analysis.
        
        Args:
            findings: List of findings to analyze
            original_content: Original scanned content
            context: Scan context
            start_delimiter: Start delimiter for content
            end_delimiter: End delimiter for content
            analyzers_used: List of analyzer names used
            
        Returns:
            User prompt string
        """
        # Convert findings to serializable format
        findings_data = []
        for i, finding in enumerate(findings):
            finding_dict = self._finding_to_dict(finding)
            finding_dict["_index"] = i
            findings_data.append(finding_dict)

        findings_json = json.dumps(findings_data, indent=2)
        
        # Truncate content if too long
        max_content_length = 8000
        if len(original_content) > max_content_length:
            truncated_content = original_content[:max_content_length] + "\n...[TRUNCATED]..."
        else:
            truncated_content = original_content

        context_str = json.dumps(context, indent=2) if context else "{}"
        analyzers_str = ", ".join(analyzers_used) if analyzers_used else "Unknown"

        return f"""## Security Findings to Analyze

The following findings were detected by multiple security analyzers ({analyzers_str}). Please perform meta-analysis to:
1. Identify false positives that should be filtered out
2. Prioritize findings by actual exploitability and impact
3. Identify correlations between related findings
4. Provide specific, actionable recommendations and fixes

### Scan Context
```json
{context_str}
```

### Findings from Analyzers
```json
{findings_json}
```

### Original Scanned Content
{start_delimiter}
{truncated_content}
{end_delimiter}

Please provide your meta-analysis as a JSON object with the structure defined in the system prompt."""

    def _parse_meta_response(
        self, response: str, original_findings: List[SecurityFinding]
    ) -> MetaAnalysisResult:
        """Parse the LLM meta-analysis response.
        
        Args:
            response: LLM response text
            original_findings: Original findings for reference
            
        Returns:
            MetaAnalysisResult with parsed data
        """
        try:
            json_data = self._extract_json_from_response(response)
            
            result = MetaAnalysisResult(
                validated_findings=json_data.get("validated_findings", []),
                false_positives=json_data.get("false_positives", []),
                priority_order=json_data.get("priority_order", []),
                correlations=json_data.get("correlations", []),
                recommendations=json_data.get("recommendations", []),
                overall_risk_assessment=json_data.get("overall_risk_assessment", {}),
            )
            
            # Enrich validated findings with original data if needed
            self._enrich_findings(result, original_findings)
            
            return result

        except (json.JSONDecodeError, ValueError) as e:
            self.logger.error(f"Failed to parse meta-analysis response: {e}")
            self.logger.debug(f"Response preview: {response[:500]}...")
            
            # Return original findings as validated
            return MetaAnalysisResult(
                validated_findings=[self._finding_to_dict(f) for f in original_findings],
                overall_risk_assessment={
                    "risk_level": "UNKNOWN",
                    "summary": "Failed to parse meta-analysis response",
                }
            )

    def _extract_json_from_response(self, response_content: str) -> Dict[str, Any]:
        """Extract JSON from LLM response using multiple strategies.
        
        Args:
            response_content: Raw LLM response
            
        Returns:
            Parsed JSON object
            
        Raises:
            ValueError: If response cannot be parsed
        """
        if not response_content or not response_content.strip():
            raise ValueError("Empty response from LLM")

        # Strategy 1: Parse entire response as JSON
        try:
            return json.loads(response_content.strip())
        except json.JSONDecodeError:
            pass

        # Strategy 2: Extract from markdown code blocks
        try:
            json_start_marker = "```json"
            json_end_marker = "```"
            
            start_idx = response_content.find(json_start_marker)
            if start_idx != -1:
                content_start = start_idx + len(json_start_marker)
                end_idx = response_content.find(json_end_marker, content_start)
                
                if end_idx != -1:
                    json_str = response_content[content_start:end_idx].strip()
                    return json.loads(json_str)
                else:
                    json_str = response_content[content_start:].strip()
                    json_str = self._attempt_fix_truncated_json(json_str)
                    return json.loads(json_str)
        except json.JSONDecodeError:
            pass

        # Strategy 3: Find JSON object by balanced braces
        try:
            start_idx = response_content.find("{")
            if start_idx != -1:
                brace_count = 0
                end_idx = -1

                for i in range(start_idx, len(response_content)):
                    if response_content[i] == "{":
                        brace_count += 1
                    elif response_content[i] == "}":
                        brace_count -= 1
                        if brace_count == 0:
                            end_idx = i + 1
                            break

                if end_idx != -1:
                    json_content = response_content[start_idx:end_idx]
                    return json.loads(json_content)
                else:
                    json_content = response_content[start_idx:]
                    json_content = self._attempt_fix_truncated_json(json_content)
                    return json.loads(json_content)

            raise ValueError("No JSON object found in response")

        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in response: {e}")

    def _attempt_fix_truncated_json(self, json_str: str) -> str:
        """Attempt to fix truncated JSON by closing open structures.
        
        Args:
            json_str: Potentially truncated JSON string
            
        Returns:
            JSON string with attempted fixes
        """
        open_braces = json_str.count("{") - json_str.count("}")
        open_brackets = json_str.count("[") - json_str.count("]")
        
        in_string = False
        escape_next = False
        for char in json_str:
            if escape_next:
                escape_next = False
                continue
            if char == "\\":
                escape_next = True
                continue
            if char == '"':
                in_string = not in_string
        
        if in_string:
            json_str += '"'
        
        json_str += "]" * open_brackets
        json_str += "}" * open_braces
        
        return json_str

    def _enrich_findings(
        self, result: MetaAnalysisResult, original_findings: List[SecurityFinding]
    ) -> None:
        """Enrich findings with original data.
        
        Args:
            result: Meta-analysis result to enrich
            original_findings: Original findings for reference
        """
        original_lookup = {}
        for i, finding in enumerate(original_findings):
            original_lookup[i] = self._finding_to_dict(finding)

        # Enrich validated findings
        for finding in result.validated_findings:
            idx = finding.get("_index")
            if idx is not None and idx in original_lookup:
                original = original_lookup[idx]
                for key, value in original.items():
                    if key not in finding:
                        finding[key] = value

        # Enrich false positives
        for finding in result.false_positives:
            idx = finding.get("_index")
            if idx is not None and idx in original_lookup:
                original = original_lookup[idx]
                for key, value in original.items():
                    if key not in finding:
                        finding[key] = value

    def get_prioritized_findings(
        self, meta_result: MetaAnalysisResult
    ) -> List[Dict[str, Any]]:
        """Get findings sorted by priority.
        
        Args:
            meta_result: Meta-analysis result
            
        Returns:
            List of findings sorted by priority (highest first)
        """
        findings = meta_result.validated_findings
        priority_order = meta_result.priority_order

        if priority_order:
            priority_map = {idx: i for i, idx in enumerate(priority_order)}
            sorted_findings = sorted(
                findings,
                key=lambda f: priority_map.get(f.get("_index", 999), 999)
            )
            return sorted_findings
        
        # Fallback: sort by severity
        severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "SAFE": 3, "UNKNOWN": 4}
        return sorted(
            findings,
            key=lambda f: severity_order.get(f.get("severity", "UNKNOWN"), 4)
        )

    def format_recommendations(
        self, meta_result: MetaAnalysisResult
    ) -> str:
        """Format recommendations as human-readable text.
        
        Args:
            meta_result: Meta-analysis result
            
        Returns:
            Formatted recommendations string
        """
        if not meta_result.recommendations:
            return "No specific recommendations."

        lines = ["## Security Recommendations\n"]
        
        for i, rec in enumerate(meta_result.recommendations, 1):
            priority = rec.get("priority", "MEDIUM")
            title = rec.get("title", f"Recommendation {i}")
            description = rec.get("description", "No description provided")
            fix = rec.get("fix", "")
            affected = rec.get("affected_findings", [])

            lines.append(f"### {i}. [{priority}] {title}\n")
            lines.append(f"{description}\n")
            
            if fix:
                lines.append(f"**Recommended Fix:**\n```\n{fix}\n```\n")
            
            if affected:
                lines.append(f"**Addresses findings:** {', '.join(map(str, affected))}\n")
            
            lines.append("")

        return "\n".join(lines)

    def get_summary_report(self, meta_result: MetaAnalysisResult) -> Dict[str, Any]:
        """Generate a summary report from meta-analysis.
        
        Args:
            meta_result: Meta-analysis result
            
        Returns:
            Summary report dictionary
        """
        validated = meta_result.validated_findings
        false_pos = meta_result.false_positives
        
        severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for finding in validated:
            severity = finding.get("severity", "UNKNOWN")
            if severity in severity_counts:
                severity_counts[severity] += 1

        total = len(validated) + len(false_pos)
        return {
            "total_original_findings": total,
            "validated_findings_count": len(validated),
            "false_positives_count": len(false_pos),
            "false_positive_rate": (
                len(false_pos) / total * 100 if total > 0 else 0
            ),
            "severity_breakdown": severity_counts,
            "correlation_groups": len(meta_result.correlations),
            "recommendations_count": len(meta_result.recommendations),
            "overall_risk": meta_result.overall_risk_assessment,
        }
