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
import re
import secrets
from typing import Any, Dict, List, Optional, Tuple
from litellm import acompletion

from ...config.config import Config
from ...config.constants import MCPScannerConstants
from ...threats.threats import LLM_THREAT_MAPPING
from ...utils.analyzer_errors import (
    ErrorKind,
    build_infrastructure_error_finding,
    classify_analyzer_error,
    retry_transient_async,
)
from ..evidence import llm_threat_evidence
from .base import BaseAnalyzer, SecurityFinding

_DELIMITER_RE = re.compile(r"<!---UNTRUSTED_INPUT_(?:START|END)_[0-9a-f]+--->")


def _threat_items(
    threat_analysis: Dict[str, Any],
) -> List[Tuple[str, str, List[Any]]]:
    """One row per threat: name, reason, and the citations that name it."""
    if "findings" in threat_analysis:
        rows: List[Tuple[str, str, List[Any]]] = []
        raw_findings = threat_analysis.get("findings")
        if not isinstance(raw_findings, list):
            return rows
        for item in raw_findings:
            if not isinstance(item, dict):
                continue
            name = item.get("threat_name") or item.get("threat") or ""
            if not isinstance(name, str) or not name:
                continue
            reason = item.get("reason") if isinstance(item.get("reason"), str) else ""
            citations = item.get("citations")
            if not isinstance(citations, list):
                citations = []
            rows.append((name, reason, citations))
        return rows

    names = threat_analysis.get("primary_threats") or []
    if not isinstance(names, list):
        return []
    citations = threat_analysis.get("citations") or []
    if not isinstance(citations, list):
        citations = []
    rows = []
    for name in names:
        if not isinstance(name, str) or not name:
            continue
        matched = [
            citation
            for citation in citations
            if isinstance(citation, dict) and citation.get("threat") == name
        ]
        rows.append((name, "", matched))
    return rows


def _strip_trailing_newline(value: str) -> str:
    return value[:-1] if value.endswith("\n") else value


def _is_json_text(text: str) -> bool:
    try:
        json.loads(text.strip())
    except json.JSONDecodeError:
        return False
    return True


def _consume_line(text: str) -> Tuple[str, str]:
    """Return the first line and the remainder after it."""
    newline = text.find("\n")
    if newline == -1:
        return text, ""
    return text[:newline], text[newline + 1 :]


def _after_header(text: str, label: str) -> Optional[str]:
    header = label + ":"
    if not text.startswith(header):
        return None
    rest = text[len(header) :]
    if rest.startswith(" "):
        rest = rest[1:]
    return rest


def _last_json_marker(text: str, marker: str, end_marker: Optional[str]) -> Optional[int]:
    """Last ``marker`` whose following text, up to ``end_marker``, is JSON.

    An earlier copy of the marker inside the untrusted field stays in that
    field. The scanner's own suffix is the last one that parses.
    """
    pos = text.rfind(marker)
    while pos != -1:
        suffix = text[pos + len(marker) :]
        if suffix.startswith(" "):
            suffix = suffix[1:]
        if end_marker:
            end = suffix.find(end_marker)
            candidate = suffix if end == -1 else suffix[:end]
        else:
            candidate = suffix
        if _is_json_text(candidate):
            return pos
        pos = text.rfind(marker, 0, pos)
    return None


def _labeled_sections(content: str) -> Dict[str, str]:
    """Split a scanner wrapper without cutting on labels inside the text.

    Each wrapper has a fixed header order. A repeated or colliding label
    stays in the field that contains it. ``Messages``, ``Content``, and
    ``Instructions`` keep every character after their real header.
    """
    if not isinstance(content, str) or not content:
        return {}
    if content.startswith("Tool Name:"):
        return _split_tool_sections(content)
    if content.startswith("Prompt Name:"):
        return _split_prompt_sections(content)
    if content.startswith("Resource URI:"):
        return _split_resource_sections(content)
    if content.startswith("Server Name:"):
        return _split_instruction_sections(content)
    return {}


def _split_tool_sections(content: str) -> Dict[str, str]:
    rest = _after_header(content, "Tool Name")
    if rest is None:
        return {}
    name, rest = _consume_line(rest)
    sections = {"Tool Name": name}
    described = _after_header(rest, "Description")
    if described is None:
        sections["Description"] = _strip_trailing_newline(rest)
        return sections
    marker = "\nParameters Schema:"
    pos = _last_json_marker(described, marker, None)
    if pos is None:
        sections["Description"] = _strip_trailing_newline(described)
        return sections
    sections["Description"] = described[:pos]
    schema = described[pos + len(marker) :]
    if schema.startswith(" "):
        schema = schema[1:]
    sections["Parameters Schema"] = _strip_trailing_newline(schema)
    return sections


def _split_prompt_sections(content: str) -> Dict[str, str]:
    rest = _after_header(content, "Prompt Name")
    if rest is None:
        return {}
    name, rest = _consume_line(rest)
    sections = {"Prompt Name": name}
    described = _after_header(rest, "Description")
    if described is None:
        described = rest
    marker = "\nArguments:"
    pos = _last_json_marker(described, marker, "\nMessages:\n")
    if pos is None:
        sections["Description"] = _strip_trailing_newline(described)
        return sections
    sections["Description"] = described[:pos]
    suffix = described[pos + len(marker) :]
    if suffix.startswith(" "):
        suffix = suffix[1:]
    messages = suffix.find("\nMessages:\n")
    if messages == -1:
        sections["Arguments"] = _strip_trailing_newline(suffix)
        return sections
    sections["Arguments"] = suffix[:messages]
    sections["Messages"] = _strip_trailing_newline(suffix[messages + len("\nMessages:\n") :])
    return sections


def _split_resource_sections(content: str) -> Dict[str, str]:
    rest = _after_header(content, "Resource URI")
    if rest is None:
        return {}
    uri, rest = _consume_line(rest)
    sections = {"Resource URI": uri}
    for label in ("Resource Name", "Name"):
        named = _after_header(rest, label)
        if named is None:
            continue
        name, rest = _consume_line(named)
        sections[label] = name
        break
    described = _after_header(rest, "Description")
    if described is None:
        described = rest
    marker = "\nMIME Type:"
    pos = described.rfind(marker)
    chosen = None
    while pos != -1:
        suffix = described[pos + len(marker) :]
        if suffix.startswith(" "):
            suffix = suffix[1:]
        line_end = suffix.find("\n")
        if line_end != -1 and suffix[line_end + 1 :].startswith("Content:\n"):
            chosen = pos
            break
        pos = described.rfind(marker, 0, pos)
    if chosen is None:
        sections["Description"] = _strip_trailing_newline(described)
        return sections
    sections["Description"] = described[:chosen]
    suffix = described[chosen + len(marker) :]
    if suffix.startswith(" "):
        suffix = suffix[1:]
    line_end = suffix.find("\n")
    sections["MIME Type"] = suffix if line_end == -1 else suffix[:line_end]
    if line_end != -1 and suffix[line_end + 1 :].startswith("Content:\n"):
        body = suffix[line_end + 1 + len("Content:\n") :]
        sections["Content"] = _strip_trailing_newline(body)
    return sections


def _split_instruction_sections(content: str) -> Dict[str, str]:
    rest = content
    sections: Dict[str, str] = {}
    for label in ("Server Name", "Protocol Version"):
        nxt = _after_header(rest, label)
        if nxt is None:
            break
        value, rest = _consume_line(nxt)
        sections[label] = value
    instructed = _after_header(rest, "Instructions")
    if instructed is None:
        sections["Instructions"] = _strip_trailing_newline(rest)
        return sections
    sections["Instructions"] = _strip_trailing_newline(instructed)
    return sections


def _mcp_fields(context: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Original MCP fields supplied by the caller, when it still has them."""
    if not isinstance(context, dict) or not isinstance(context.get("mcp_fields"), dict):
        return None
    raw = context["mcp_fields"]
    fields: Dict[str, Any] = {}
    for key in ("name", "description", "body", "instructions"):
        value = raw.get(key)
        if isinstance(value, str) and value:
            fields[key] = value
    for key in ("parameters", "arguments"):
        value = raw.get(key)
        if isinstance(value, (dict, list)) and value:
            fields[key] = value
    return fields


def _json_value(text: Optional[str]) -> Any:
    if not isinstance(text, str) or not text.strip():
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


def _analyzed_fields(
    entity_kind: str,
    entity_name: str,
    content: str,
    context: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """Original MCP fields. The labeled wrapper is not a verified field."""
    supplied = _mcp_fields(context)
    if supplied is not None:
        if (
            "name" not in supplied
            and "instructions" not in supplied
            and isinstance(entity_name, str)
            and entity_name
            and entity_name != "Unknown Tool"
        ):
            supplied["name"] = entity_name
        return supplied
    fields: Dict[str, Any] = {}
    if (
        isinstance(entity_name, str)
        and entity_name
        and entity_name != "Unknown Tool"
    ):
        fields["name"] = entity_name
    sections = _labeled_sections(content or "")
    content_type = ""
    if isinstance(context, dict) and isinstance(context.get("content_type"), str):
        content_type = context["content_type"]

    if content_type == "instructions" or (
        "Instructions" in sections and "Description" not in sections
    ):
        text = sections.get("Instructions")
        if isinstance(text, str) and text:
            fields["instructions"] = text
        elif not sections and isinstance(content, str) and content.strip():
            fields["instructions"] = content.strip()
        fields.pop("name", None)
        return fields

    if (
        entity_kind == "prompt"
        or "Messages" in sections
        or "Arguments" in sections
    ):
        description = sections.get("Description", "")
        if description:
            fields["description"] = description
        arguments = _json_value(sections.get("Arguments"))
        if arguments is not None:
            fields["arguments"] = arguments
        body = sections.get("Messages", "")
        if body:
            fields["body"] = body
        return fields

    if entity_kind == "resource" or "Content" in sections:
        description = sections.get("Description", "")
        if description:
            fields["description"] = description
        body = sections.get("Content", "")
        if body:
            fields["body"] = body
        return fields

    parsed: Any = None
    if not sections and isinstance(content, str) and content.strip():
        try:
            parsed = json.loads(content)
        except json.JSONDecodeError:
            parsed = None
    if isinstance(parsed, dict):
        description = parsed.get("description")
        if isinstance(description, str) and description:
            fields["description"] = description
        schema = parsed.get("inputSchema")
        if not isinstance(schema, dict):
            schema = parsed.get("parameters")
        if isinstance(schema, dict):
            fields["parameters"] = schema
        return fields

    description = sections.get("Description", "")
    if description:
        fields["description"] = description
    elif not sections and isinstance(content, str) and content.strip():
        fields["description"] = content
    schema = _json_value(sections.get("Parameters Schema"))
    if isinstance(schema, dict):
        fields["parameters"] = schema
    return fields


def _delimiter_citation(fields: Dict[str, Any]) -> List[Dict[str, str]]:
    """Quote a delimiter tag when the scanned text contains one."""
    for key in ("description", "body", "name", "instructions"):
        text = fields.get(key)
        if not isinstance(text, str):
            continue
        match = _DELIMITER_RE.search(text)
        if match:
            return [{"field_hint": key, "quote": match.group(0)}]
    return []


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
            self.logger.error("Failed to load LLM prompt: %s", type(e).__name__)
            raise IOError(f"Could not load prompt {prompt_file_name}: {e}")

    def _create_threat_analysis_prompt(
        self,
        entity_name: str,
        description: str = None,
        parameters: Dict[str, Any] = None,
        entity_kind: str = "tool",
        body_text: str = None,
        _context: Optional[Dict[str, Any]] = None,
    ) -> tuple[str, bool]:
        """Create a threat analysis prompt for tools, resources, or prompts.

        Args:
            entity_name: Name of the tool, resource, or prompt
            description: Description or list metadata (optional)
            parameters: Tool parameters schema (optional; ignored for resource/prompt)
            entity_kind: ``tool``, ``resource``, or ``prompt``
            body_text: Resource/prompt body from ``read_resource`` / ``get_prompt``
            _context: Additional context (unused)

        Returns:
            Tuple of (formatted prompt string, prompt_injection_detected)
            prompt_injection_detected is True if delimiter injection was detected
        """
        # Generate random delimiter tags to prevent prompt injection
        random_id = secrets.token_hex(16)
        start_tag = f"<!---UNTRUSTED_INPUT_START_{random_id}--->"
        end_tag = f"<!---UNTRUSTED_INPUT_END_{random_id}--->"

        if entity_kind in ("resource", "prompt"):
            label = "Resource" if entity_kind == "resource" else "Prompt"
            analysis_content = f"{label} Name: {entity_name}\n"
            if description and description.strip():
                analysis_content += f"Metadata:\n{description.strip()}\n"
            analysis_content += f"Body:\n{(body_text or '').strip()}\n"
            analysis_content += "Parameters:\n  Not applicable\n"
        else:
            # The whole schema, including enum, const, default, examples, and pattern.
            if parameters:
                params_text = json.dumps(parameters, indent=2, default=str)
            else:
                params_text = "  No parameters"

            analysis_content = f"Tool Name: {entity_name}\n"
            if description:
                analysis_content += f"Description: {description}\n"
            analysis_content += f"Parameters:\n{params_text}"

        # Security validation: Check that the untrusted input doesn't contain our delimiter tags
        prompt_injection_detected = False
        if start_tag in analysis_content or end_tag in analysis_content:
            self.logger.warning(
                f"Potential prompt injection detected in {entity_kind} {entity_name}: "
                "Input contains delimiter tags"
            )
            prompt_injection_detected = True

        # Create the updated protection rules with randomized delimiters
        updated_protection_rules = self._protection_rules.replace(
            "<!---UNTRUSTED_INPUT_START--->", start_tag
        ).replace("<!---UNTRUSTED_INPUT_END--->", end_tag)

        prompt = f"""{updated_protection_rules}

        {self._threat_analysis_prompt}

        {start_tag}
        {analysis_content}
        {end_tag}
        """

        return prompt.strip(), prompt_injection_detected

    @staticmethod
    def _completion_text(response: Any) -> str:
        """Extract non-empty text from a LiteLLM chat completion."""
        try:
            content = response.choices[0].message.content
        except (AttributeError, IndexError, TypeError):
            return ""
        return (content or "").strip()

    @staticmethod
    def _completion_finish_reason(response: Any) -> str:
        try:
            reason = response.choices[0].finish_reason
        except (AttributeError, IndexError, TypeError):
            return ""
        return str(reason or "")

    @staticmethod
    def _extract_mcp_entity_body(content: str, entity_kind: str) -> str:
        """Extract analyzable body text from scanner-formatted resource/prompt content."""
        if not content:
            return ""
        if entity_kind == "resource":
            marker = "Content:\n"
        elif entity_kind == "prompt":
            marker = "Messages:\n"
        else:
            return content.strip()
        idx = content.find(marker)
        if idx == -1:
            # No rendered messages or resource content. The formatted
            # string is metadata only; returning it would present name,
            # description, and arguments as the body.
            return ""
        return content[idx + len(marker) :].strip()

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
            self.logger.error(
                "Failed to parse LLM response as JSON: %s", type(e).__name__
            )
            self.logger.error(
                f"Response content length: {len(response_content)} characters"
            )
            raise ValueError("Invalid JSON in LLM response") from e
        except Exception as e:
            self.logger.error(
                "Unexpected error parsing LLM response: %s", type(e).__name__
            )
            self.logger.error(
                f"Response content length: {len(response_content)} characters"
            )
            raise ValueError("Failed to parse LLM response") from e

    def _create_findings_from_threat_analysis(
        self,
        analysis_result: Dict[str, Any],
        tool_name: str,
        analyzed_fields: Optional[Dict[str, str]] = None,
        entity_kind: str = "tool",
    ) -> List[SecurityFinding]:
        """Create security findings from threat analysis."""
        findings = []

        threat_analysis = analysis_result.get("threat_analysis", {})

        # Only create findings if malicious content is detected AND primary threats are specified
        if not isinstance(threat_analysis, dict):
            threat_analysis = {}
        if threat_analysis.get("malicious_content_detected") is False:
            return findings
        threat_items = _threat_items(threat_analysis)
        if not threat_items:
            return findings
        if (
            "findings" not in threat_analysis
            and not threat_analysis.get("malicious_content_detected")
        ):
            return findings

        consumed_quotes: set = set()
        threat_names = [item[0] for item in threat_items]
        for threat_name, reason, citations in threat_items:
            threat_info = LLM_THREAT_MAPPING.get(threat_name)
            if threat_info:
                category = threat_info["threat_category"]
                display_name = threat_info["threat_type"]
                severity = threat_info["severity"]
            else:
                category = threat_name
                display_name = threat_name.lower().replace("_", " ")
                severity = "UNKNOWN"
            if category == "SAFE":
                continue
            summary = reason.strip() if isinstance(reason, str) and reason.strip() else (
                f"{display_name} detected in tool content"
            )
            finding = SecurityFinding(
                severity=severity,
                summary=summary,
                analyzer="LLM",
                threat_category=category,
                details={
                    "tool_name": tool_name,
                    "threat_type": threat_name,
                    "evidence": f"{display_name} detected in tool content",
                    "raw_response": analysis_result,
                    "primary_threats": threat_names,
                },
                evidence=llm_threat_evidence(
                    summary,
                    citations,
                    analyzed_fields,
                    entity_kind,
                    consumed_quotes,
                ),
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
        if context:
            entity_name = (
                context.get("tool_name")
                or context.get("prompt_name")
                or context.get("resource_name")
            )
        else:
            entity_name = None
        entity_name = entity_name or "Unknown Tool"
        if context and context.get("entity_type") == "resource":
            entity_kind = "resource"
        elif context and (
            context.get("prompt_name") or context.get("entity_type") == "prompt"
        ):
            entity_kind = "prompt"
        else:
            entity_kind = "tool"

        try:
            # Parse the content to extract tool information
            tool_info = self._parse_tool_content(content, context)
            findings = []
            analyzed_fields = _analyzed_fields(
                entity_kind, entity_name, content, context
            )
            body_text = analyzed_fields.get("body") or ""
            if not isinstance(body_text, str):
                body_text = ""
            description_text = analyzed_fields.get("description") or ""
            if not isinstance(description_text, str):
                description_text = ""
            if entity_kind in ("resource", "prompt"):
                prompt_description = description_text
                arguments = analyzed_fields.get("arguments")
                if arguments is not None:
                    rendered = (
                        arguments
                        if isinstance(arguments, str)
                        else json.dumps(arguments, indent=2)
                    )
                    prompt_description = f"{description_text}\nArguments:\n{rendered}".strip()
            elif analyzed_fields.get("instructions") and not description_text:
                prompt_description = analyzed_fields["instructions"]
            else:
                prompt_description = tool_info.get("description") or description_text

            has_tool_fields = bool(prompt_description) or bool(
                tool_info.get("parameters")
            )
            has_body = bool(body_text.strip())
            if has_tool_fields or has_body:
                threat_prompt, prompt_injection_detected = (
                    self._create_threat_analysis_prompt(
                        entity_name,
                        description=prompt_description,
                        parameters=tool_info.get("parameters"),
                        entity_kind=entity_kind,
                        body_text=body_text if entity_kind in ("resource", "prompt") else None,
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
                            "tool_name": entity_name,
                            "threat_type": "PROMPT INJECTION",
                            "evidence": "prompt injection detected in tool content",
                            "primary_threats": ["PROMPT INJECTION"],
                        },
                        evidence=llm_threat_evidence(
                            "Detected 1 threat: prompt injection",
                            _delimiter_citation(analyzed_fields),
                            analyzed_fields,
                            entity_kind,
                            set(),
                        ),
                    )
                    findings.append(finding)
                else:
                    messages = [
                        {
                            "role": "system",
                            "content": (
                                f"You are a security expert analyzing MCP {entity_kind}s "
                                "for threats. Follow the analysis framework provided."
                            ),
                        },
                        {"role": "user", "content": threat_prompt},
                    ]
                    max_attempts = self._max_retries + 1
                    threat_content = ""
                    finish_reason = ""
                    for attempt in range(1, max_attempts + 1):
                        threat_response = await self._make_llm_request(
                            messages=messages,
                            context=f"threat analysis for {entity_name}",
                        )
                        threat_content = self._completion_text(threat_response)
                        finish_reason = self._completion_finish_reason(
                            threat_response
                        )
                        if threat_content:
                            break
                        self.logger.warning(
                            "Empty LLM completion for %s (attempt %d/%d, "
                            "finish_reason=%s) — retrying",
                            entity_name,
                            attempt,
                            max_attempts,
                            finish_reason or "unknown",
                        )
                        if attempt < max_attempts:
                            await asyncio.sleep(self._rate_limit_delay)

                    if not threat_content:
                        empty_error = ValueError(
                            "Empty response from LLM after "
                            f"{max_attempts} attempt(s)"
                            + (
                                f" (finish_reason={finish_reason})"
                                if finish_reason
                                else ""
                            )
                        )
                        self.logger.warning(
                            "LLM threat analysis skipped after %d empty attempt(s)",
                            max_attempts,
                        )
                        findings.append(
                            build_infrastructure_error_finding(
                                analyzer_name="LLM",
                                subject=entity_name,
                                error=empty_error,
                                model=self._model,
                                safe_reason="empty_response",
                            )
                        )
                    else:
                        threat_analysis = self._parse_response(threat_content)
                        threat_findings = self._create_findings_from_threat_analysis(
                            threat_analysis,
                            entity_name,
                            analyzed_fields,
                            entity_kind,
                        )
                        findings.extend(threat_findings)

            return findings

        except Exception as e:
            self.logger.error("LLM analysis failed: %s", type(e).__name__)
            return [
                build_infrastructure_error_finding(
                    analyzer_name="LLM",
                    subject=entity_name,
                    error=e,
                    model=self._model,
                )
            ]

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
        supplied = _mcp_fields(context)
        if supplied is not None:
            description = supplied.get("description")
            if isinstance(description, str):
                tool_info["description"] = description
            parameters = supplied.get("parameters")
            if isinstance(parameters, (dict, list)):
                tool_info["parameters"] = parameters
            return tool_info

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
            return tool_info
        except json.JSONDecodeError:
            pass

        sections = _labeled_sections(content)
        if sections:
            tool_info["description"] = sections.get("Description", "")
            schema = _json_value(sections.get("Parameters Schema"))
            if isinstance(schema, (dict, list)):
                tool_info["parameters"] = schema
            return tool_info

        # Plain text (a docstring or description), not a labeled wrapper.
        tool_info["description"] = content
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
        from mcpscanner.utils.llm_request_params import apply_model_constraints

        max_attempts = self._max_retries + 1

        async def operation() -> Any:
            self.logger.debug(
                "LLM API request for %s (max_attempts=%d)",
                context,
                max_attempts,
            )
            request_params = {
                "model": self._model,
                "messages": messages,
                "max_tokens": self._max_tokens,
                "temperature": self._temperature,
                "timeout": self._llm_timeout,
            }
            apply_model_constraints(self._model, request_params)

            if self._api_key:
                request_params["api_key"] = self._api_key
            if self._base_url:
                request_params["api_base"] = self._base_url
            if self._api_version:
                request_params["api_version"] = self._api_version
            if self._aws_region:
                request_params["aws_region_name"] = self._aws_region
            if self._aws_session_token:
                request_params["aws_session_token"] = self._aws_session_token
            if self._aws_profile_name:
                request_params["aws_profile_name"] = self._aws_profile_name

            return await acompletion(**request_params, drop_params=True)

        async def on_retry(
            exc: BaseException, attempt: int, delay: float
        ) -> None:
            self.logger.warning(
                "LLM API transient error, retrying in %.1fs "
                "(attempt %d/%d): %s",
                delay,
                attempt,
                max_attempts,
                type(exc).__name__,
            )

        try:
            return await retry_transient_async(
                operation,
                max_attempts=max_attempts,
                base_delay=self._rate_limit_delay,
                model=self._model,
                on_retry=on_retry,
            )
        except Exception as e:
            kind = classify_analyzer_error(e, context="llm", model=self._model)
            if kind is ErrorKind.FINAL:
                self.logger.error("LLM API final error: %s", type(e).__name__)
            else:
                self.logger.error(
                    "LLM API transient error, retries exhausted: %s",
                    type(e).__name__,
                )
            raise
