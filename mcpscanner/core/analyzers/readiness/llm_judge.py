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
LLM Judge for Readiness Analysis.

DISABLED BY DEFAULT - requires explicit configuration via environment
variables. This module provides LLM-based semantic analysis for readiness
issues that are difficult to detect with static heuristic checks.

Supports any LiteLLM-compatible model:
- OpenAI: gpt-4, gpt-3.5-turbo
- Anthropic: claude-3-opus, claude-3-sonnet
- Local: ollama/llama2, ollama/mistral
- Azure: azure/gpt-4
- AWS Bedrock: bedrock/anthropic.claude-3-sonnet

To enable, set MCP_SCANNER_LLM_API_KEY environment variable.
"""

import json
import os
from typing import Any, Dict, List, Optional

from ....config.constants import MCPScannerConstants
from ....utils.logging_config import get_logger
from ..base import SecurityFinding

# Try to import litellm
_litellm_available = False
_litellm_import_error: Optional[str] = None

try:
    from litellm import acompletion

    _litellm_available = True
except ImportError as e:
    _litellm_import_error = str(e)
    acompletion = None  # type: ignore


# Readiness-specific threat categories
READINESS_THREAT_CATEGORIES = {
    "actionable_errors": "MISSING_ERROR_SCHEMA",
    "failure_modes": "SILENT_FAILURE_PATH",
    "scope_clarity": "OVERLOADED_TOOL_SCOPE",
}


class ReadinessLLMJudge:
    """
    LLM-based semantic analysis for readiness issues.

    DISABLED BY DEFAULT - requires MCP_SCANNER_LLM_API_KEY environment
    variable to be set.

    This class provides semantic analysis capabilities that complement
    the heuristic-based ReadinessAnalyzer. It evaluates aspects of tool
    definitions that require understanding of context and intent:

    - Is the error handling actionable for humans and agents?
    - Are failure modes clearly documented?
    - Is the tool's scope appropriately focused?

    Example:
        >>> from mcpscanner.core.analyzers.readiness import ReadinessLLMJudge
        >>> judge = ReadinessLLMJudge()
        >>> if judge.is_available():
        ...     findings = await judge.analyze(tool_definition)
        ... else:
        ...     print(judge.get_unavailable_reason())
    """

    def __init__(
        self,
        model: Optional[str] = None,
        api_key: Optional[str] = None,
        api_base: Optional[str] = None,
        temperature: float = 0.1,
        max_tokens: int = 1024,
        enabled_evaluations: Optional[List[str]] = None,
    ) -> None:
        """
        Initialize the LLM judge for readiness analysis.

        Args:
            model: LiteLLM model identifier. Defaults to MCP_SCANNER_LLM_MODEL
                   environment variable or 'gpt-4o'.
            api_key: API key for the LLM provider. Defaults to
                     MCP_SCANNER_LLM_API_KEY environment variable.
            api_base: Optional API base URL for self-hosted models.
            temperature: LLM temperature (lower = more deterministic).
            max_tokens: Maximum response tokens.
            enabled_evaluations: List of evaluation IDs to run. Valid values:
                                 'actionable_errors', 'failure_modes', 'scope_clarity'.
                                 Defaults to all evaluations.
        """
        self.model = (
            model
            or os.environ.get(MCPScannerConstants.ENV_LLM_MODEL)
            or MCPScannerConstants.DEFAULT_LLM_MODEL
        )
        self.api_key = api_key or os.environ.get(MCPScannerConstants.ENV_LLM_API_KEY)
        self.api_base = (
            api_base
            or os.environ.get("MCP_SCANNER_LLM_BASE_URL")
            or MCPScannerConstants.DEFAULT_LLM_BASE_URL
        )
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.enabled_evaluations = enabled_evaluations or [
            "actionable_errors",
            "failure_modes",
            "scope_clarity",
        ]
        self._prompt_template: Optional[str] = None
        self.logger = get_logger(f"{__name__}.ReadinessLLMJudge")

    def is_available(self) -> bool:
        """
        Check if LLM judge is available.

        DISABLED by default - requires:
        1. litellm package installed
        2. MCP_SCANNER_LLM_API_KEY environment variable set

        Returns:
            True if the LLM judge can be used, False otherwise.
        """
        if not _litellm_available:
            return False

        # Require API key to be set
        return bool(self.api_key)

    def get_unavailable_reason(self) -> Optional[str]:
        """
        Get explanation for why LLM judge is unavailable.

        Returns:
            Human-readable explanation or None if available.
        """
        if not _litellm_available:
            return f"litellm not installed: {_litellm_import_error}"

        if not self.api_key:
            return (
                "Readiness LLM judge disabled by default. Set MCP_SCANNER_LLM_API_KEY "
                "environment variable to enable semantic analysis."
            )

        return None

    def _load_prompt_template(self) -> str:
        """Load the readiness judge prompt template."""
        if self._prompt_template is not None:
            return self._prompt_template

        try:
            prompt_path = (
                MCPScannerConstants.get_prompts_path() / "readiness_judge_prompt.md"
            )
            self._prompt_template = prompt_path.read_text(encoding="utf-8")
            return self._prompt_template
        except Exception as e:
            self.logger.error(f"Failed to load readiness judge prompt: {e}")
            # Return a minimal fallback prompt
            return (
                "Analyze this MCP tool definition for production readiness issues. "
                "Respond with JSON containing: actionable_errors, failure_modes, "
                "scope_clarity assessments."
            )

    async def analyze(
        self,
        tool_definition: Dict[str, Any],
        tool_name: Optional[str] = None,
    ) -> List[SecurityFinding]:
        """
        Analyze a tool definition using LLM semantic evaluation.

        Args:
            tool_definition: The tool definition dictionary to analyze.
            tool_name: Optional tool name for findings. Extracted from
                       tool_definition if not provided.

        Returns:
            List of SecurityFinding objects for readiness issues detected.
            Returns empty list if LLM judge is unavailable.
        """
        if not self.is_available():
            self.logger.debug(
                f"Readiness LLM judge unavailable: {self.get_unavailable_reason()}"
            )
            return []

        if tool_name is None:
            tool_name = tool_definition.get("name", "unknown")

        findings: List[SecurityFinding] = []
        tool_json = json.dumps(tool_definition, indent=2)

        try:
            result = await self._run_evaluation(tool_json)
            findings = self._results_to_findings(result, tool_name)
        except Exception as e:
            self.logger.error(f"LLM readiness evaluation failed for {tool_name}: {e}")
            # Don't add error findings - just log and return empty
            # This prevents polluting results when LLM is temporarily unavailable

        return findings

    async def _run_evaluation(self, tool_json: str) -> Dict[str, Any]:
        """Run the LLM evaluation on a tool definition."""
        prompt_template = self._load_prompt_template()
        prompt = f"{prompt_template}\n\n{tool_json}"

        # Build request parameters
        request_params = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are an expert at evaluating MCP tool definitions "
                        "for production readiness. Respond only with valid JSON."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }

        # Add API key if available
        if self.api_key:
            request_params["api_key"] = self.api_key

        # Add base URL if configured
        if self.api_base:
            request_params["api_base"] = self.api_base

        response = await acompletion(**request_params)

        # Parse response
        content = response.choices[0].message.content
        return self._parse_response(content)

    def _parse_response(self, content: str) -> Dict[str, Any]:
        """Parse LLM response and extract JSON."""
        try:
            # Handle markdown code blocks
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0]
            elif "```" in content:
                content = content.split("```")[1].split("```")[0]

            return json.loads(content.strip())
        except json.JSONDecodeError as e:
            self.logger.warning(f"Failed to parse LLM response as JSON: {e}")
            return {"error": "Failed to parse LLM response", "raw": content}

    def _results_to_findings(
        self,
        result: Dict[str, Any],
        tool_name: str,
    ) -> List[SecurityFinding]:
        """Convert LLM evaluation results to SecurityFinding objects."""
        findings: List[SecurityFinding] = []

        # Check for parse errors
        if "error" in result:
            self.logger.warning(f"LLM evaluation error: {result.get('error')}")
            return []

        readiness_analysis = result.get("readiness_analysis", {})

        # Process each enabled evaluation
        for eval_id in self.enabled_evaluations:
            finding = self._process_evaluation(
                eval_id, readiness_analysis, tool_name, result
            )
            if finding:
                findings.append(finding)

        return findings

    def _process_evaluation(
        self,
        eval_id: str,
        readiness_analysis: Dict[str, Any],
        tool_name: str,
        full_result: Dict[str, Any],
    ) -> Optional[SecurityFinding]:
        """Process a single evaluation result into a SecurityFinding."""
        # Map evaluation IDs to result keys and check fields
        eval_mapping = {
            "actionable_errors": {
                "key": "actionable_errors",
                "check_field": "is_actionable",
                "question": "Does the tool provide actionable error handling?",
                "suggestions_field": "suggestions",
            },
            "failure_modes": {
                "key": "failure_modes",
                "check_field": "clearly_documented",
                "question": "Are failure modes clearly documented?",
                "suggestions_field": "missing_documentation",
            },
            "scope_clarity": {
                "key": "scope_clarity",
                "check_field": "is_appropriate",
                "question": "Is the tool's scope appropriately focused?",
                "suggestions_field": "concerns",
            },
        }

        mapping = eval_mapping.get(eval_id)
        if not mapping:
            return None

        eval_result = readiness_analysis.get(mapping["key"], {})
        if not eval_result:
            return None

        # Check if there's an issue
        is_passing = eval_result.get(mapping["check_field"], True)
        if is_passing:
            return None

        confidence = eval_result.get("confidence", 0.5)
        reasoning = eval_result.get("reasoning", "")
        suggestions = eval_result.get(mapping["suggestions_field"], [])

        # Determine severity based on confidence
        if confidence >= 0.8:
            severity = "MEDIUM"
        elif confidence >= 0.6:
            severity = "LOW"
        else:
            severity = "INFO"

        # Get threat category
        threat_category = READINESS_THREAT_CATEGORIES.get(
            eval_id, "OVERLOADED_TOOL_SCOPE"
        )

        # Build summary
        summary = f"Readiness issue: {mapping['question']}"

        # Build details
        details = {
            "tool_name": tool_name,
            "rule_id": f"LLM-READINESS-{eval_id.upper().replace('_', '-')}",
            "location": f"tool.{tool_name}",
            "llm_reasoning": reasoning,
            "confidence": confidence,
            "model": self.model,
            "recommendations": suggestions,
            "raw_response": full_result,
        }

        return SecurityFinding(
            severity=severity,
            summary=summary,
            analyzer="READINESS-LLM",
            threat_category=threat_category,
            details=details,
        )

