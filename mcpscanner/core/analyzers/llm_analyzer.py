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

"""LLM Analyzer module for MCP Scanner SDK.

This module contains the LLM analyzer class for analyzing MCP tools using any LLM-supported model
via LiteLLM to detect malicious content and data exfiltration risks.
"""

import asyncio
import json
import secrets
from typing import Any, Dict, List, Optional
from litellm import acompletion

from ...config.config import Config
from ...config.constants import MCPScannerConstants
from ...threats.threats import LLM_THREAT_MAPPING
from .base import BaseAnalyzer, SecurityFinding


class SecurityError(Exception):
    """Custom exception for security violations in LLM prompts."""

    pass


class LLMAnalyzer(BaseAnalyzer):
    """Analyzer class for analyzing MCP tools using any LLM-supported model.

    This analyzer examines MCP tool descriptions, function names,
    and parameters for malicious content and data exfiltration risks using advanced LLM analysis
    model through the LiteLLM library.

    Example:
        >>> from mcpscanner import Config
        >>> from mcpscanner.analyzers import LLMAnalyzer
        >>> config = Config(llm_provider_api_key="your_llm_provider_api_key")
        >>> analyzer = LLMAnalyzer(config)
        >>> findings = await analyzer.analyze("Tool description to analyze")
        >>> if not findings:
        ...     pass  # Tool is safe
        ... else:
        ...     pass  # Found security findings
    """

    def __init__(self, config: Config):
        """Initialize a new LLMAnalyzer instance.

        Args:
            config (Config): The configuration for the analyzer.
        """
        super().__init__("LLMAnalyzer")
        self._config = config

        # Get model configuration from config
        self._model = config.llm_model

        # Detect Bedrock model
        is_bedrock = self._model and "bedrock/" in self._model

        # Authentication strategy based on provider:
        # 1. Non-Bedrock providers (OpenAI, Anthropic, etc.): API key required
        # 2. Bedrock with API key: Use Bedrock API key (MCP_SCANNER_LLM_API_KEY)
        # 3. Bedrock with bearer token: Use AWS_BEARER_TOKEN_BEDROCK for API gateway auth
        # 4. Bedrock without API key: Use AWS credentials (profile/IAM/session token)

        if not is_bedrock:
            # Non-Bedrock providers always require API key
            if (
                not hasattr(config, "llm_provider_api_key")
                or not config.llm_provider_api_key
            ):
                raise ValueError("LLM provider API key is required for LLM analyzer")
            self._api_key = config.llm_provider_api_key
        else:
            # Bedrock: Check for API key, then bearer token, then fall back to AWS credentials
            if hasattr(config, "llm_provider_api_key") and config.llm_provider_api_key:
                # Use Bedrock API key authentication (MCP_SCANNER_LLM_API_KEY)
                self._api_key = config.llm_provider_api_key
                self.logger.debug("Bedrock: Using API key authentication (MCP_SCANNER_LLM_API_KEY)")
            elif hasattr(config, "aws_bearer_token_bedrock") and config.aws_bearer_token_bedrock:
                # Use AWS Bedrock bearer token (AWS_BEARER_TOKEN_BEDROCK)
                self._api_key = config.aws_bearer_token_bedrock
                self.logger.debug("Bedrock: Using bearer token authentication (AWS_BEARER_TOKEN_BEDROCK)")
            else:
                # Use AWS credentials (profile/IAM/session token)
                self._api_key = None
                self.logger.debug(
                    "Bedrock: Using AWS credentials (profile/IAM/session)"
                )

        # Store configuration for per-request usage
        self._base_url = config.llm_base_url
        self._api_version = config.llm_api_version
        self._max_tokens = config.llm_max_tokens
        self._temperature = config.llm_temperature
        self._rate_limit_delay = config.llm_rate_limit_delay
        self._max_retries = config.llm_max_retries

        # AWS Bedrock configuration (only used for Bedrock models)
        self._aws_region = config.aws_region_name if is_bedrock else None
        self._aws_session_token = config.aws_session_token if is_bedrock else None
        self._aws_profile_name = config.aws_profile_name if is_bedrock else None
        self._llm_timeout = config.llm_timeout

        # Load shared protection rules and analysis prompts
        self._protection_rules = self._load_prompt(
            "boilerplate_protection_rule_prompt.md"
        )
        self._threat_analysis_prompt = self._load_prompt("threat_analysis_prompt.md")

    def _load_prompt(self, prompt_file_name: str) -> str:
        """Load a prompt from a markdown file.

        Args:
            prompt_file_name (str): The name of the prompt file.

        Returns:
            str: The prompt content.

        Raises:
            FileNotFoundError: If the prompt file cannot be found.
            IOError: If the prompt file cannot be read.
        """
        try:
            prompt_file = MCPScannerConstants.get_prompts_path() / prompt_file_name

            if not prompt_file.is_file():
                raise FileNotFoundError(f"Prompt file not found: {prompt_file_name}")

            return prompt_file.read_text(encoding="utf-8")

        except FileNotFoundError:
            self.logger.error(f"Prompt file not found: {prompt_file_name}")
            raise
        except Exception as e:
            self.logger.error(f"Failed to load prompt {prompt_file_name}: {e}")
            raise IOError(f"Could not load prompt {prompt_file_name}: {e}")

    def _create_threat_analysis_prompt_parts(
        self,
        tool_name: str,
        description: str = None,
        parameters: Dict[str, Any] = None,
        _context: Optional[Dict[str, Any]] = None,
    ) -> tuple[str, str, bool]:
        """Build the threat-analysis prompt as a (system, user, injection_flag) split.

        The framework prompts (~19 KB combined: ``boilerplate_protection_rule_prompt.md``
        plus ``threat_analysis_prompt.md``) used to be concatenated into the
        ``user`` message. That works against most providers but is the
        wrong role assignment — the framework is static instructions, the
        user message should carry only the per-call evidence. Splitting
        it brings LLMAnalyzer in line with the behavioral path's
        Bedrock-friendly shape (see
        ``AlignmentPromptBuilder.build_prompt_parts``).

        The two halves share the same random delimiter id so the
        protection rules in the system prompt can reference the exact
        delimited block emitted in the user prompt.

        Returns:
            Tuple ``(system_prompt, user_payload, prompt_injection_detected)``:

            * ``system_prompt`` — protection rules + threat analysis
              framework. Belongs in the ``system`` role.
            * ``user_payload`` — the ``<!---UNTRUSTED_INPUT_*--->``-wrapped
              per-tool evidence. Belongs in the ``user`` role.
            * ``prompt_injection_detected`` — True if the untrusted
              input contained one of our delimiter tags (the caller
              short-circuits and emits a PROMPT INJECTION finding
              instead of forwarding to the LLM).
        """
        random_id = secrets.token_hex(16)
        start_tag = f"<!---UNTRUSTED_INPUT_START_{random_id}--->"
        end_tag = f"<!---UNTRUSTED_INPUT_END_{random_id}--->"

        if parameters:
            param_list = []
            for param_name, param_info in parameters.items():
                param_type = param_info.get("type", "unknown")
                param_desc = param_info.get("description", "No description")
                param_list.append(f"  - {param_name} ({param_type}): {param_desc}")
            params_text = "\n".join(param_list)
        else:
            params_text = "  No parameters"

        analysis_content = f"Tool Name: {tool_name}\n"
        if description:
            analysis_content += f"Description: {description}\n"
        analysis_content += f"Parameters:\n{params_text}"

        prompt_injection_detected = False
        if start_tag in analysis_content or end_tag in analysis_content:
            self.logger.warning(
                f"Potential prompt injection detected in tool {tool_name}: Input contains delimiter tags"
            )
            prompt_injection_detected = True

        # Substitute the random delimiters into the protection rules so
        # the rules' references like "anything between START and END is
        # untrusted" line up with what we actually emit in the user role.
        updated_protection_rules = self._protection_rules.replace(
            "<!---UNTRUSTED_INPUT_START--->", start_tag
        ).replace("<!---UNTRUSTED_INPUT_END--->", end_tag)

        system_prompt = (
            f"{updated_protection_rules}\n\n{self._threat_analysis_prompt}"
        ).strip()
        user_payload = f"{start_tag}\n{analysis_content}\n{end_tag}"

        return system_prompt, user_payload, prompt_injection_detected

    def _create_threat_analysis_prompt(
        self,
        tool_name: str,
        description: str = None,
        parameters: Dict[str, Any] = None,
        _context: Optional[Dict[str, Any]] = None,
    ) -> tuple[str, bool]:
        """Backward-compatible wrapper around :meth:`_create_threat_analysis_prompt_parts`.

        Returns the legacy single-string concatenated prompt (system
        framework followed by the delimited user evidence). Callers
        should prefer the parts API; this exists so external code that
        hasn't migrated still works.
        """
        system_prompt, user_payload, prompt_injection_detected = (
            self._create_threat_analysis_prompt_parts(
                tool_name,
                description=description,
                parameters=parameters,
                _context=_context,
            )
        )
        prompt = f"{system_prompt}\n\n{user_payload}"
        return prompt.strip(), prompt_injection_detected

    @staticmethod
    def _validate_threat_analysis_shape(parsed: Any) -> None:
        """Confirm the parsed LLM response carries the expected schema.

        Raises ``ValueError`` when the response is structurally unusable
        (not a dict, missing the ``threat_analysis`` key, or the inner
        object is missing the two fields downstream code reads). This is
        the same "couldn't verify" → ``severity=ERROR`` distinction the
        behavioral path enforces via ``AlignmentVerificationError``:
        previously a Bedrock ``{}`` short-circuit silently produced an
        empty findings list, conflating "verified clean" with "couldn't
        verify".

        Notes:
            * A *well-formed* clean response (``threat_analysis`` present
              with ``malicious_content_detected=False`` and
              ``primary_threats=[]``) passes this check and continues
              through ``_create_findings_from_threat_analysis``, which
              correctly emits zero findings — the legitimate clean case.
            * Unknown extra keys are allowed; the LLM is welcome to
              decorate the response.
        """
        if not isinstance(parsed, dict):
            raise ValueError(
                f"LLM response is not a JSON object "
                f"(got {type(parsed).__name__})"
            )
        threat_analysis = parsed.get("threat_analysis")
        if threat_analysis is None:
            raise ValueError(
                "LLM response missing required 'threat_analysis' key "
                f"(got keys: {sorted(parsed.keys())})"
            )
        if not isinstance(threat_analysis, dict):
            raise ValueError(
                f"LLM response 'threat_analysis' is not a JSON object "
                f"(got {type(threat_analysis).__name__})"
            )
        # The two fields downstream consumers always read.
        # ``malicious_content_detected`` gates whether to emit findings;
        # ``primary_threats`` is the list iterated to build them. A
        # response missing either is ambiguous — could be "clean" or
        # could be Bedrock-truncated. Treat as "couldn't verify".
        for required in ("malicious_content_detected", "primary_threats"):
            if required not in threat_analysis:
                raise ValueError(
                    f"LLM response 'threat_analysis' missing required "
                    f"field '{required}' (got keys: "
                    f"{sorted(threat_analysis.keys())})"
                )

    def _create_llm_unavailable_finding(
        self, tool_name: str, error: BaseException
    ) -> SecurityFinding:
        """Build a ``severity=ERROR`` sentinel finding for verification failures.

        Mirrors the behavioral path's ``LLM_UNAVAILABLE_KEY`` /
        ``_create_llm_unavailable_finding`` pattern so consumers can
        treat unverified-tool rows uniformly across the LLM and
        behavioral analyzers. The finding:

          * Has ``severity="ERROR"`` so it never collapses into the
            ``HIGH``/``MEDIUM``/``LOW``/``SAFE`` aggregate buckets.
          * Has an empty ``threat_category`` so it doesn't pollute
            threat-name aggregates.
          * Marks ``details.llm_unavailable=True`` so consumers can
            filter/route ERROR rows separately from any future
            ERROR-severity sources.
          * Carries the truncated error message so operators can debug
            without re-running with logging enabled.
        """
        error_message = str(error) if error is not None else ""
        # Truncate to keep findings.json artefacts small. Full traces
        # still go to the analyzer log via ``exc_info=True``.
        truncated = error_message[:500]
        return SecurityFinding(
            severity="ERROR",
            summary=(
                f"LLM verification failed for tool '{tool_name}': "
                f"{error_message[:200]}"
            ),
            analyzer="LLM",
            threat_category="",
            details={
                "tool_name": tool_name,
                "llm_unavailable": True,
                "error_type": (
                    type(error).__name__ if error is not None else "Unknown"
                ),
                "error_message": truncated,
            },
        )

    def _parse_response(self, response_content: str) -> Dict[str, Any]:
        """Parse the LLM response and extract analysis results.

        Args:
            response_content (str): The raw response content from the LLM.

        Returns:
            Dict[str, Any]: Parsed analysis results.

        Raises:
            ValueError: If the response cannot be parsed as valid JSON.
        """
        if not response_content or not response_content.strip():
            raise ValueError("Empty response from LLM")

        try:
            # First, try to parse the entire response as JSON
            return json.loads(response_content.strip())
        except json.JSONDecodeError:
            pass

        try:
            # Try to extract JSON from the response by finding balanced braces
            response_content = response_content.strip()

            # Look for JSON object boundaries
            start_idx = response_content.find("{")
            if start_idx == -1:
                raise ValueError("No JSON object found in LLM response")

            # Find the matching closing brace
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

            if end_idx == -1:
                raise ValueError("No matching closing brace found in JSON")

            json_content = response_content[start_idx:end_idx]

            return json.loads(json_content)

        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse LLM response as JSON: {e}")
            self.logger.error(
                f"Response content length: {len(response_content)} characters"
            )
            raise ValueError(f"Invalid JSON in LLM response: {e}")
        except Exception as e:
            self.logger.error(f"Unexpected error parsing LLM response: {e}")
            self.logger.error(
                f"Response content length: {len(response_content)} characters"
            )
            raise ValueError(f"Failed to parse LLM response: {e}")

    def _create_findings_from_threat_analysis(
        self, analysis_result: Dict[str, Any], tool_name: str
    ) -> List[SecurityFinding]:
        """Create security findings from threat analysis."""
        findings = []

        threat_analysis = analysis_result.get("threat_analysis", {})
        primary_threats = threat_analysis.get("primary_threats", [])

        # Only create findings if malicious content is detected AND primary threats are specified
        if primary_threats and threat_analysis.get(
            "malicious_content_detected", False
        ):
            # Generate threat summary for all findings
            display_names = []
            for threat_name in primary_threats:
                threat_info = LLM_THREAT_MAPPING.get(threat_name)
                if threat_info:
                    display_names.append(threat_info["threat_type"])

            if len(display_names) == 1:
                threat_summary = f"Detected 1 threat: {display_names[0]}"
            else:
                threat_summary = f"Detected {len(display_names)} threats: {', '.join(display_names)}"

            # Create specific findings for each detected threat
            for threat_name in primary_threats:
                threat_info = LLM_THREAT_MAPPING.get(threat_name)

                if threat_info:
                    category = threat_info["threat_category"]
                    display_name = threat_info["threat_type"]
                    # Use severity from centralized threat mapping
                    severity = threat_info["severity"]
                else:
                    # Handle unknown threats by using the threat name itself
                    category = threat_name
                    display_name = threat_name.lower().replace("_", " ")
                    severity = "UNKNOWN"

                # Skip creating findings only for explicitly SAFE classifications
                if category == "SAFE":
                    continue

                finding = SecurityFinding(
                    severity=severity,
                    summary=threat_summary,
                    analyzer="LLM",
                    threat_category=category,
                    details={
                        "tool_name": tool_name,
                        "threat_type": threat_name,  # Original name for taxonomy lookup
                        "evidence": f"{display_name} detected in tool content",
                        "raw_response": analysis_result,
                        "primary_threats": primary_threats,
                    },
                )
                findings.append(finding)
        return findings

    async def analyze(
        self, content: str, context: Optional[Dict[str, Any]] = None
    ) -> List[SecurityFinding]:
        """Analyze the provided content for malicious intent and return security findings.

        Args:
            content (str): The content to analyze (tool description, function name, parameters).
            context (Optional[Dict[str, Any]]): Additional context for the analysis.
                Can include 'tool_name' for better logging and analysis.

        Returns:
            List[SecurityFinding]: The security findings found during the analysis.

        Raises:
            Exception: If the LLM API request fails.
        """
        tool_name = (
            context.get("tool_name", "Unknown Tool") if context else "Unknown Tool"
        )

        try:
            # Parse the content to extract tool information
            tool_info = self._parse_tool_content(content, context)
            findings = []

            # Threat Analysis: Analyze tool name, description, and parameters together
            if tool_info.get("description") or tool_info.get("parameters"):
                # Use the (system, user) split — keeps the ~19 KB
                # framework prompts in the system role and only the
                # delimited per-tool evidence in the user role. This
                # matches the behavioral path and keeps Bedrock from
                # mistaking the framework for a chat turn it has to
                # respond *to*.
                system_prompt, user_payload, prompt_injection_detected = (
                    self._create_threat_analysis_prompt_parts(
                        tool_name,
                        description=tool_info.get("description"),
                        parameters=tool_info.get("parameters"),
                        _context=context,
                    )
                )

                # If prompt injection is detected, create a PROMPT INJECTION finding
                if prompt_injection_detected:
                    finding = SecurityFinding(
                        severity="HIGH",
                        summary="Detected 1 threat: prompt injection",
                        analyzer="LLM",
                        threat_category="PROMPT INJECTION",
                        details={
                            "tool_name": tool_name,
                            "threat_type": "PROMPT INJECTION",
                            "evidence": "prompt injection detected in tool content",
                            "primary_threats": ["PROMPT INJECTION"],
                        },
                    )
                    findings.append(finding)
                else:
                    # No prompt injection detected, proceed with normal LLM analysis
                    threat_response = await self._make_llm_request(
                        messages=[
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": user_payload},
                        ],
                        context=f"threat analysis for {tool_name}",
                    )

                    threat_content = threat_response.choices[0].message.content
                    threat_analysis = self._parse_response(threat_content)
                    # Reject empty-{} / missing-fields / non-dict
                    # responses up front. These were previously routed
                    # through ``_create_findings_from_threat_analysis``
                    # which silently returned [] for any input lacking
                    # the expected schema — collapsing "couldn't verify"
                    # into "verified clean".
                    self._validate_threat_analysis_shape(threat_analysis)
                    threat_findings = self._create_findings_from_threat_analysis(
                        threat_analysis, tool_name
                    )
                    findings.extend(threat_findings)

            return findings

        except Exception as e:
            # Verification could not complete (transport failure,
            # parser failure, schema validation failure). Emit a
            # ``severity="ERROR"`` sentinel finding so the absence of
            # findings is never confused with "verified clean". This
            # mirrors the behavioral path's LLM_UNAVAILABLE sentinel
            # pattern. The full traceback still lands in the analyzer
            # log; only a 500-char truncated message goes on the
            # finding to keep findings.json artefacts small.
            self.logger.error(f"LLM analysis failed for {tool_name}: {str(e)}")
            self.logger.error(f"Full traceback for {tool_name}:", exc_info=True)
            return [self._create_llm_unavailable_finding(tool_name, e)]

    def _parse_tool_content(
        self, content: str, context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Parse tool content to extract description and parameters.

        Args:
            content (str): The tool content to parse.
            context (Optional[Dict[str, Any]]): Additional context.

        Returns:
            Dict[str, Any]: Parsed tool information with description and parameters.
        """
        tool_info = {"description": "", "parameters": {}}

        # Handle None or empty content
        if not content:
            return tool_info

        try:
            # Try to parse as JSON first (for structured tool definitions)
            parsed_content = json.loads(content)

            if isinstance(parsed_content, dict):
                tool_info["description"] = parsed_content.get("description", "")

                # Extract parameters from various possible structures
                if "parameters" in parsed_content:
                    tool_info["parameters"] = parsed_content["parameters"]
                elif "inputSchema" in parsed_content:
                    properties = parsed_content["inputSchema"].get("properties", {})
                    tool_info["parameters"] = properties

        except json.JSONDecodeError:
            # If not JSON, treat as plain text (likely a docstring or description)
            tool_info["description"] = content

            # Try to extract parameter information from context if available
            if context and "parameters" in context:
                tool_info["parameters"] = context["parameters"]

        return tool_info

    async def _make_llm_request(
        self, messages: List[Dict[str, str]], context: str = ""
    ) -> Any:
        """Make an LLM request with retry logic and exponential backoff.

        Args:
            messages: The messages to send to the LLM
            context: Context string for logging

        Returns:
            The LLM response object

        Raises:
            Exception: If all retries are exhausted
        """
        last_exception = None

        for attempt in range(self._max_retries + 1):
            try:
                self.logger.debug(
                    f"LLM API attempt {attempt + 1}/{self._max_retries + 1} for {context}"
                )

                # Build request parameters with per-request configuration
                request_params = {
                    "model": self._model,
                    "messages": messages,
                    "max_tokens": self._max_tokens,
                    "temperature": self._temperature,
                    "timeout": self._llm_timeout,
                }

                # Add API key if set (works for OpenAI, Anthropic, and Bedrock API keys)
                # For Bedrock: api_key can be a Bedrock API key (AWS_BEARER_TOKEN_BEDROCK)
                # If not set, Bedrock will use AWS credentials (profile/IAM role)
                if self._api_key:
                    request_params["api_key"] = self._api_key

                # Add base URL if configured (for Azure OpenAI or custom endpoints)
                if self._base_url:
                    request_params["api_base"] = self._base_url

                # Add API version if configured (required for Azure OpenAI)
                if self._api_version:
                    request_params["api_version"] = self._api_version

                # Add AWS region for Bedrock
                if self._aws_region:
                    request_params["aws_region_name"] = self._aws_region

                # Add AWS session token for temporary credentials
                if self._aws_session_token:
                    request_params["aws_session_token"] = self._aws_session_token

                # Add AWS profile for credential resolution
                if self._aws_profile_name:
                    request_params["aws_profile_name"] = self._aws_profile_name

                response = await acompletion(**request_params)
                return response

            except Exception as e:
                last_exception = e
                error_msg = str(e).lower()

                # Check for AWS/Bedrock specific errors (only for Bedrock models)
                is_bedrock_model = self._model and "bedrock/" in self._model
                if is_bedrock_model and any(
                    keyword in error_msg
                    for keyword in [
                        "bedrockexception",
                        "throttlingexception",
                    ]
                ):
                    self.logger.error(
                        f"AWS Bedrock error for {context}: {e}. "
                        "Check AWS credentials, region, and Bedrock model access."
                    )
                    if attempt < self._max_retries:
                        delay = (2**attempt) * self._rate_limit_delay
                        self.logger.warning(
                            f"Retrying AWS Bedrock request in {delay}s "
                            f"(attempt {attempt + 1}/{self._max_retries + 1})"
                        )
                        await asyncio.sleep(delay)
                        continue
                    else:
                        break

                # Check if it's a rate limiting error
                if any(
                    keyword in error_msg
                    for keyword in ["rate limit", "quota", "too many requests", "429"]
                ):
                    if attempt < self._max_retries:
                        # Exponential backoff: 2^attempt * base_delay
                        delay = (2**attempt) * self._rate_limit_delay
                        self.logger.warning(
                            f"Rate limit hit for {context}, retrying in {delay}s (attempt {attempt + 1}/{self._max_retries + 1})"
                        )
                        await asyncio.sleep(delay)
                        continue
                    else:
                        self.logger.error(
                            f"Rate limit exceeded for {context}, no more retries"
                        )
                        break
                else:
                    # For non-rate-limit errors, don't retry
                    self.logger.error(f"LLM API error for {context}: {e}")
                    break

        # If we get here, all retries failed
        raise last_exception
