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

"""LLM Meta-Analyzer for MCP Scanner.

Performs a second-pass LLM analysis with a single, narrow purpose:
**filter false positives** from the findings produced by other analyzers.

The meta-analyzer never:

- Adds new findings (no "missed threats" enrichment).
- Promotes, re-scores, or enriches true positives that an analyzer flagged.
- Attaches recommendations, correlations, or risk assessments to findings.

It only removes findings that the LLM judges to be benign given the entity
context. If an analyzer did not flag something, the meta-analyzer will not
synthesize a finding for it.

Requirements:
    - Enable via CLI --enable-meta flag
    - Requires LLM API key (uses same config as LLM analyzer)
"""

from __future__ import annotations

import asyncio
import json
import secrets
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from litellm import acompletion

from ...config.config import Config
from ...config.constants import MCPScannerConstants
from ...utils.logging_config import get_logger
from .base import SecurityFinding

logger = get_logger(__name__)


@dataclass
class MetaAnalysisResult:
    """Result of meta-analysis on security findings.

    Attributes:
        validated_findings: Findings confirmed as true positives with enrichment.
        false_positives: Findings identified as likely false positives.
        missed_threats: NEW threats found by meta-analyzer that other analyzers missed.
        priority_order: Ordered list of finding indices by priority (highest first).
        correlations: Groups of related findings.
        recommendations: Actionable recommendations for remediation.
        overall_risk_assessment: Summary risk assessment for the entity.
    """

    validated_findings: List[Dict[str, Any]] = field(default_factory=list)
    false_positives: List[Dict[str, Any]] = field(default_factory=list)
    missed_threats: List[Dict[str, Any]] = field(default_factory=list)
    priority_order: List[int] = field(default_factory=list)
    correlations: List[Dict[str, Any]] = field(default_factory=list)
    recommendations: List[Dict[str, Any]] = field(default_factory=list)
    overall_risk_assessment: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        return {
            "validated_findings": self.validated_findings,
            "false_positives": self.false_positives,
            "missed_threats": self.missed_threats,
            "priority_order": self.priority_order,
            "correlations": self.correlations,
            "recommendations": self.recommendations,
            "overall_risk_assessment": self.overall_risk_assessment,
            "summary": {
                "total_original": len(self.validated_findings) + len(self.false_positives),
                "validated_count": len(self.validated_findings),
                "false_positive_count": len(self.false_positives),
                "missed_threats_count": len(self.missed_threats),
                "recommendations_count": len(self.recommendations),
            },
        }


class MetaAnalyzer:
    """LLM-based meta-analyzer for reviewing and refining security findings.

    This analyzer performs a second-pass analysis on findings from all other
    analyzers to provide expert-level security assessment. It:
    - Filters false positives using contextual understanding
    - Prioritizes findings by actual risk
    - Correlates related findings across analyzers
    - Detects threats that other analyzers may have missed
    - Provides specific remediation recommendations

    The meta-analyzer runs AFTER all other analyzers complete.

    Example:
        >>> meta = MetaAnalyzer(config)
        >>> result = await meta.analyze_findings(findings, analyzers_used, entity_context)
        >>> enriched = apply_meta_analysis(original_findings, result)
    """

    def __init__(self, config: Config):
        """Initialize the Meta Analyzer.

        Uses the same LLM configuration as the LLM analyzer (from Config),
        with higher max_tokens and timeout for the larger meta-analysis payloads.

        Args:
            config: Scanner configuration (provides LLM model, API key, etc.)

        Raises:
            ImportError: If litellm is not installed.
            ValueError: If LLM API key is not configured (non-Bedrock models).
        """
        self.name = "META"
        self._logger = get_logger(f"{__name__}.MetaAnalyzer")

        self._model = config.llm_model
        is_bedrock = self._model and "bedrock/" in self._model

        if not is_bedrock:
            if not config.llm_provider_api_key:
                raise ValueError(
                    "Meta-Analyzer LLM API key not configured. "
                    "Set MCP_SCANNER_LLM_API_KEY environment variable."
                )
            self._api_key = config.llm_provider_api_key
        else:
            if config.llm_provider_api_key:
                self._api_key = config.llm_provider_api_key
            elif hasattr(config, "aws_bearer_token_bedrock") and config.aws_bearer_token_bedrock:
                self._api_key = config.aws_bearer_token_bedrock
            else:
                self._api_key = None

        self._base_url = config.llm_base_url
        self._api_version = config.llm_api_version
        self._aws_region = config.aws_region_name if is_bedrock else None
        self._aws_session_token = config.aws_session_token if is_bedrock else None
        self._aws_profile_name = config.aws_profile_name if is_bedrock else None

        self._max_tokens = 8192
        self._temperature = 0.1
        self._max_retries = config.llm_max_retries
        self._timeout = max(config.llm_timeout, 120.0)
        self._rate_limit_delay = config.llm_rate_limit_delay

        self._system_prompt = self._load_prompt()

    def _load_prompt(self) -> str:
        """Load meta-analysis prompt template from file."""
        try:
            prompt_file = MCPScannerConstants.get_prompts_path() / "meta_analysis_prompt.md"
            if hasattr(prompt_file, "read_text"):
                return prompt_file.read_text(encoding="utf-8")
            with open(str(prompt_file), encoding="utf-8") as f:
                return f.read()
        except Exception as e:
            self._logger.warning("Failed to load meta-analysis prompt: %s", e)
            return (
                "You are a senior security analyst performing meta-analysis on MCP security findings. "
                "Review findings from multiple analyzers, identify false positives, "
                "prioritize by actual risk, correlate related issues, and provide actionable recommendations. "
                "Respond with JSON containing your analysis following the required schema."
            )

    async def analyze_findings(
        self,
        findings: List[SecurityFinding],
        analyzers_used: List[str],
        entity_context: Dict[str, Any],
    ) -> MetaAnalysisResult:
        """Perform meta-analysis on findings from other analyzers.

        Args:
            findings: List of findings from all other analyzers.
            analyzers_used: Names of analyzers that produced the findings.
            entity_context: Context about the entity being scanned, e.g.
                ``{"type": "tool", "name": "...", "description": "...", "parameters": {...}}``.

        Returns:
            MetaAnalysisResult with validated findings, false positives, and recommendations.
        """
        if not findings:
            return MetaAnalysisResult(
                overall_risk_assessment={
                    "risk_level": "SAFE",
                    "summary": "No security findings to analyze — entity appears safe.",
                }
            )

        random_id = secrets.token_hex(16)
        start_tag = f"<!---ENTITY_CONTENT_START_{random_id}--->"
        end_tag = f"<!---ENTITY_CONTENT_END_{random_id}--->"

        findings_data = self._serialize_findings(findings)
        user_prompt = self._build_user_prompt(
            entity_context=entity_context,
            findings_data=findings_data,
            analyzers_used=analyzers_used,
            start_tag=start_tag,
            end_tag=end_tag,
        )

        try:
            response = await self._make_llm_request(self._system_prompt, user_prompt)
            result = self._parse_response(response, findings)

            self._logger.info(
                "Meta-analysis complete: %d false positive(s) flagged for filtering out of %d findings",
                len(result.false_positives),
                len(findings),
            )
            return result

        except Exception as e:
            # On failure we deliberately do nothing: no FP suggestions means
            # apply_meta_analysis will keep every analyzer finding as-is.
            self._logger.error(
                "Meta-analysis failed (%s); keeping all original findings.", e
            )
            return MetaAnalysisResult(
                overall_risk_assessment={
                    "risk_level": "UNKNOWN",
                    "summary": f"Meta-analysis failed: {e}. Original findings preserved.",
                },
            )

    def _serialize_findings(self, findings: List[SecurityFinding]) -> str:
        """Serialize findings to JSON for the prompt."""
        findings_list = []
        for i, f in enumerate(findings):
            entry: Dict[str, Any] = {
                "_index": i,
                "severity": f.severity,
                "summary": f.summary,
                "threat_category": f.threat_category,
                "analyzer": f.analyzer,
            }
            if f.details:
                if "threat_type" in f.details:
                    entry["threat_type"] = f.details["threat_type"]
                if "evidence" in f.details:
                    evidence = f.details["evidence"]
                    entry["evidence"] = evidence[:300] if isinstance(evidence, str) else str(evidence)[:300]
                if "tool_name" in f.details:
                    entry["tool_name"] = f.details["tool_name"]
            findings_list.append(entry)
        return json.dumps(findings_list, indent=2)

    def _build_user_prompt(
        self,
        entity_context: Dict[str, Any],
        findings_data: str,
        analyzers_used: List[str],
        start_tag: str,
        end_tag: str,
    ) -> str:
        """Build the user prompt for meta-analysis."""
        num_findings = findings_data.count('"_index"')
        entity_type = entity_context.get("type", "entity")
        entity_name = entity_context.get("name", "Unknown")
        entity_desc = entity_context.get("description", "N/A")
        parameters = entity_context.get("parameters")

        context_block = f"**{entity_type.title()}:** {entity_name}\n**Description:** {entity_desc}"
        if parameters:
            params_json = json.dumps(parameters, indent=2)
            context_block += f"\n**Parameters Schema:**\n```json\n{params_json}\n```"

        return f"""## Meta-Analysis Request — False Positive Filtering Only

You have {num_findings} findings from {len(analyzers_used)} analyzers. Your **only** job is to identify which of these findings are **false positives** that should be filtered out.

You MUST NOT:
- Suggest new threats the analyzers missed.
- Re-score, prioritize, correlate, or otherwise enrich true positives.
- Recommend remediation steps.
- Promote a benign finding to a higher severity.

You MUST:
- Treat every finding the analyzers flagged as a candidate true positive by default.
- Only mark a finding as a false positive when the actual entity context shows it is genuinely benign (e.g., keyword match in safe documentation, standard parameter name, safe library usage for stated purpose).
- Leave ambiguous findings alone — when in doubt, do NOT mark as FP.

### Analyzers Used
{", ".join(analyzers_used)}

### Entity Context
{start_tag}
{context_block}
{end_tag}

### Findings from Analyzers ({num_findings} total)
```json
{findings_data}
```

### Required Output (compact)

Respond with ONLY a JSON object with a single `false_positives` list. Indices not present are kept as-is.

```json
{{
  "false_positives": [
    {{"_index": N, "false_positive_reason": "brief reason this finding is benign in context"}}
  ]
}}
```

If no findings are false positives, return `{{"false_positives": []}}`."""

    async def _make_llm_request(self, system_prompt: str, user_prompt: str) -> str:
        """Make a request to the LLM API with retry logic."""
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

        api_params: Dict[str, Any] = {
            "model": self._model,
            "messages": messages,
            "temperature": self._temperature,
            "max_tokens": self._max_tokens,
            "timeout": float(self._timeout),
        }

        if self._api_key:
            api_params["api_key"] = self._api_key
        if self._base_url:
            api_params["api_base"] = self._base_url
        if self._api_version:
            api_params["api_version"] = self._api_version
        if self._aws_region:
            api_params["aws_region_name"] = self._aws_region
        if self._aws_session_token:
            api_params["aws_session_token"] = self._aws_session_token
        if self._aws_profile_name:
            api_params["aws_profile_name"] = self._aws_profile_name

        last_exception: Optional[Exception] = None
        for attempt in range(self._max_retries + 1):
            try:
                response = await acompletion(**api_params, drop_params=True)
                content: str = response.choices[0].message.content or ""
                return content
            except Exception as e:
                last_exception = e
                error_msg = str(e).lower()
                is_retryable = any(
                    kw in error_msg
                    for kw in ["timeout", "tls", "connection", "network", "rate limit", "throttle", "429", "503", "504"]
                )
                if attempt < self._max_retries and is_retryable:
                    delay = (2 ** attempt) * self._rate_limit_delay
                    self._logger.warning("Meta-analysis LLM request failed (attempt %d): %s", attempt + 1, e)
                    await asyncio.sleep(delay)
                else:
                    break

        if last_exception is not None:
            raise last_exception
        raise RuntimeError("All retries exhausted")

    def _parse_response(
        self, response: str, original_findings: List[SecurityFinding]
    ) -> MetaAnalysisResult:
        """Parse the LLM meta-analysis response.

        Only the ``false_positives`` field is consumed; any other fields the
        model may emit are ignored to keep the analyzer's behavior narrow.
        """
        try:
            json_data = self._extract_json_from_response(response)
            return MetaAnalysisResult(
                false_positives=list(json_data.get("false_positives", [])),
            )
        except (json.JSONDecodeError, ValueError) as e:
            # On parse failure, return an empty result so no findings are filtered.
            self._logger.error(
                "Failed to parse meta-analysis response (%s); keeping all findings.",
                e,
            )
            return MetaAnalysisResult(
                overall_risk_assessment={
                    "risk_level": "UNKNOWN",
                    "summary": "Failed to parse meta-analysis response",
                },
            )

    def _extract_json_from_response(self, response: str) -> Dict[str, Any]:
        """Extract JSON from LLM response using multiple strategies."""
        if not response or not response.strip():
            raise ValueError("Empty response from LLM")

        # Strategy 1: Parse entire response as JSON
        try:
            return json.loads(response.strip())
        except json.JSONDecodeError:
            pass

        # Strategy 2: Extract from markdown code blocks
        json_marker = "```json"
        fence_end = "```"
        start_idx = response.find(json_marker)
        if start_idx != -1:
            content_start = start_idx + len(json_marker)
            end_idx = response.find(fence_end, content_start)
            if end_idx != -1:
                try:
                    return json.loads(response[content_start:end_idx].strip())
                except json.JSONDecodeError:
                    pass

        # Strategy 3: Find JSON object by balanced braces
        start_idx = response.find("{")
        if start_idx != -1:
            brace_count = 0
            end_idx = -1
            for i in range(start_idx, len(response)):
                if response[i] == "{":
                    brace_count += 1
                elif response[i] == "}":
                    brace_count -= 1
                    if brace_count == 0:
                        end_idx = i + 1
                        break
            if end_idx != -1:
                try:
                    return json.loads(response[start_idx:end_idx])
                except json.JSONDecodeError:
                    pass

        # Strategy 4: Attempt to repair truncated JSON
        if start_idx is not None and start_idx != -1:
            json_fragment = response[start_idx:]
            open_braces = json_fragment.count("{") - json_fragment.count("}")
            open_brackets = json_fragment.count("[") - json_fragment.count("]")
            if open_braces > 0 or open_brackets > 0:
                last_good = max(
                    json_fragment.rfind("},"),
                    json_fragment.rfind("],"),
                    json_fragment.rfind("}"),
                )
                if last_good > 0:
                    repaired = json_fragment[: last_good + 1]
                    repaired += "]}" * open_brackets
                    repaired += "}" * max(0, repaired.count("{") - repaired.count("}"))
                    try:
                        result = json.loads(repaired)
                        self._logger.warning("Recovered truncated meta-analysis JSON response")
                        return result
                    except (json.JSONDecodeError, ValueError):
                        pass

        raise ValueError("No valid JSON found in response")


def apply_meta_analysis(
    original_findings: List[SecurityFinding],
    meta_result: MetaAnalysisResult,
) -> List[SecurityFinding]:
    """Apply meta-analysis results to a list of analyzer findings.

    Scope is intentionally minimal: this function only **filters out
    findings the meta-analyzer judged to be false positives**. Findings the
    meta-analyzer did not classify (or classified as true positives) are
    returned unchanged. Nothing is enriched, prioritized, correlated, or
    synthesized — if no analyzer flagged something, it does not appear in
    the output.

    A small audit trail (``meta_false_positive=True`` plus ``meta_reason``)
    is recorded on each filtered finding's details before it is dropped, so
    callers that retain the raw findings list separately can still inspect
    why a finding was removed.

    Args:
        original_findings: Original findings from all analyzers.
        meta_result: Results from meta-analysis.

    Returns:
        Findings list with meta-analyzer-identified false positives removed.
    """
    fp_data: Dict[int, Dict[str, Any]] = {}
    for fp in meta_result.false_positives:
        idx = fp.get("_index")
        if isinstance(idx, int):
            fp_data[idx] = {
                "reason": (
                    fp.get("reason")
                    or fp.get("false_positive_reason")
                    or "Identified as likely false positive"
                ),
                "confidence": fp.get("confidence"),
            }

    kept_findings: List[SecurityFinding] = []
    for i, finding in enumerate(original_findings):
        if i in fp_data:
            # Annotate before dropping so the audit trail survives on the
            # original SecurityFinding object even though it is not returned.
            if finding.details is None:
                finding.details = {}
            finding.details["meta_false_positive"] = True
            finding.details["meta_reason"] = fp_data[i]["reason"]
            if fp_data[i].get("confidence") is not None:
                finding.details["meta_confidence"] = fp_data[i]["confidence"]
            continue
        kept_findings.append(finding)

    return kept_findings
