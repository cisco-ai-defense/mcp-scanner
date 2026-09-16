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

"""Running the analyzer set over one MCP entity.

Tools, prompts, resources and server instructions each get their own function
here, but they all repeat the same move twenty-one times over: check whether an
analyzer was requested and initialized, call it, stamp its name onto the
findings, and log-and-continue if it raises. :func:`run_analyzer_pass` is that
move written once, so a change to the contract (say, recording failures instead
of swallowing them) is a change to one function.

What stays per-entity is genuinely per-entity: which analyzers apply, what
content each one sees, and how the result is assembled.
"""

import json
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from ..utils.logging_config import get_logger
from .analyzers.base import BaseAnalyzer
from .models import AnalyzerEnum
from .result import (
    InstructionsScanResult,
    PromptScanResult,
    ResourceScanResult,
    ToolScanResult,
)

logger = get_logger(__name__)

# Content is a callable when producing it is part of what the failure log
# covers -- several passes build their prompt text inside the same try block
# that guards the analyzer call.
ContentSource = Union[str, Callable[[], str]]


@dataclass
class AnalyzerBundle:
    """The analyzers available for a scan.

    Any of the built-ins may be ``None`` when the corresponding credentials or
    configuration are absent; each pass checks before running.
    """

    api: Optional[Any] = None
    yara: Optional[Any] = None
    llm: Optional[Any] = None
    readiness: Optional[Any] = None
    prompt_defense: Optional[Any] = None
    custom: List[BaseAnalyzer] = field(default_factory=list)


async def run_analyzer_pass(
    analyzer: Any,
    content: ContentSource,
    context: Dict[str, Any],
    *,
    label: str,
    failure_log: str,
) -> List[Any]:
    """Run one analyzer and return its findings stamped with ``label``.

    Never raises: a failing analyzer logs ``failure_log`` and contributes
    nothing, so one broken analyzer cannot fail the whole scan.
    """
    try:
        text = content() if callable(content) else content
        findings = await analyzer.analyze(text, context)
    except Exception as e:
        logger.error(f'{failure_log}, error="{e}"')
        return []
    for finding in findings:
        finding.analyzer = label
    return findings


async def run_custom_analyzers(
    analyzers: List[BaseAnalyzer],
    content: str,
    context: Dict[str, Any],
    http_headers: Optional[dict],
    *,
    failure_subject: str,
) -> Tuple[List[Any], List[str]]:
    """Run every custom analyzer, returning findings and the names that ran.

    A custom analyzer that raises is omitted from the returned names, so the
    result never claims coverage the scan did not actually get.
    """
    all_findings: List[Any] = []
    ran: List[str] = []
    for analyzer in analyzers:
        custom_context = dict(context)
        if http_headers:
            custom_context["http_headers"] = http_headers
        try:
            findings = await analyzer.analyze(content, custom_context)
        except Exception as e:
            logger.error(
                f'Custom analyzer "{analyzer.name}" failed{failure_subject}, error="{e}"'
            )
            continue
        for finding in findings:
            finding.analyzer = analyzer.name
        all_findings.extend(findings)
        ran.append(analyzer.name)
    return all_findings, ran


def _warn_llm_uninitialized(entity: str) -> None:
    logger.warning(
        f"LLM scan requested for {entity} but LLM analyzer not initialized "
        "(MCP_SCANNER_LLM_API_KEY missing)"
    )


def _reported_analyzers(
    analyzers: List[AnalyzerEnum], custom_names: List[str]
) -> List[Any]:
    """Analyzers to report on the result, excluding META.

    Meta-analysis enriches existing findings rather than producing its own
    output section.
    """
    return [a for a in analyzers if a != AnalyzerEnum.META] + custom_names


async def analyze_tool(
    bundle: AnalyzerBundle,
    tool: Any,
    analyzers: List[AnalyzerEnum],
    http_headers: Optional[dict] = None,
) -> ToolScanResult:
    """Analyze a single MCP tool with the requested analyzers."""
    all_findings: List[Any] = []
    name = tool.name
    description = tool.description
    tool_json = tool.model_dump_json()
    tool_data = json.loads(tool_json)

    if AnalyzerEnum.API in analyzers and bundle.api:
        all_findings += await run_analyzer_pass(
            bundle.api,
            description,
            {"tool_name": name, "content_type": "description"},
            label="API",
            failure_log=f'API analysis failed on description: tool="{name}"',
        )

    if AnalyzerEnum.YARA in analyzers:
        all_findings += await run_analyzer_pass(
            bundle.yara,
            description,
            {"tool_name": name, "content_type": "description"},
            label="YARA",
            failure_log=f'YARA analysis failed on description: tool="{name}"',
        )

        def _parameters() -> str:
            # The description was already analyzed on its own above.
            tool_data.pop("description", None)
            return json.dumps(tool_data)

        all_findings += await run_analyzer_pass(
            bundle.yara,
            _parameters,
            {"tool_name": name, "content_type": "parameters"},
            label="YARA",
            failure_log=f'YARA analysis failed on parameters: tool="{name}"',
        )

    if AnalyzerEnum.LLM in analyzers and bundle.llm:

        def _comprehensive() -> str:
            content = f"Tool Name: {name}\n"
            content += f"Description: {description}\n"
            if "inputSchema" in tool_data:
                content += (
                    f"Parameters Schema: {json.dumps(tool_data['inputSchema'], indent=2)}\n"
                )
            return content

        all_findings += await run_analyzer_pass(
            bundle.llm,
            _comprehensive,
            {"tool_name": name, "content_type": "comprehensive"},
            label="LLM",
            failure_log=f'LLM analysis failed: tool="{name}"',
        )
    elif AnalyzerEnum.LLM in analyzers and not bundle.llm:
        _warn_llm_uninitialized(f"tool \"'{name}'\"")

    if AnalyzerEnum.READINESS in analyzers and bundle.readiness:
        all_findings += await run_analyzer_pass(
            bundle.readiness,
            tool_json,
            {
                "tool_name": name,
                "content_type": "tool_definition",
                "tool_definition": tool_data,
            },
            label="READINESS",
            failure_log=f'Readiness analysis failed: tool="{name}"',
        )

    if AnalyzerEnum.PROMPT_DEFENSE in analyzers and bundle.prompt_defense:
        all_findings += await run_analyzer_pass(
            bundle.prompt_defense,
            description,
            {"tool_name": name, "content_type": "description"},
            label="PromptDefense",
            failure_log=f'Prompt defense analysis failed: tool="{name}"',
        )

    custom_findings, custom_names = await run_custom_analyzers(
        bundle.custom,
        description,
        {"tool_name": name, "content_type": "description"},
        http_headers,
        failure_subject=f': tool="{name}"',
    )
    all_findings += custom_findings

    return ToolScanResult(
        tool_name=name,
        tool_description=description,
        status="completed",
        analyzers=_reported_analyzers(analyzers, custom_names),
        findings=all_findings,
    )


async def analyze_prompt(
    bundle: AnalyzerBundle,
    prompt: Any,
    analyzers: List[AnalyzerEnum],
    http_headers: Optional[dict] = None,
) -> PromptScanResult:
    """Analyze a single MCP prompt with the requested analyzers."""
    all_findings: List[Any] = []
    name = prompt.name
    description = prompt.description or ""

    try:
        prompt_json = prompt.model_dump_json()
        prompt_data = json.loads(prompt_json)
    except (json.JSONDecodeError, AttributeError, TypeError) as e:
        logger.warning(f"Error parsing prompt '{name}' data: {e}. Using minimal data.")
        prompt_data = {"name": name, "description": description}

    if AnalyzerEnum.API in analyzers and bundle.api:
        all_findings += await run_analyzer_pass(
            bundle.api,
            description,
            {"prompt_name": name, "content_type": "description"},
            label="API",
            failure_log=f'API analysis failed on prompt description: prompt="{name}"',
        )

    if AnalyzerEnum.YARA in analyzers:
        all_findings += await run_analyzer_pass(
            bundle.yara,
            description,
            {"prompt_name": name, "content_type": "description"},
            label="YARA",
            failure_log=f'YARA analysis failed on prompt description: prompt="{name}"',
        )

        def _arguments() -> str:
            # The description was already analyzed on its own above.
            prompt_data.pop("description", None)
            return json.dumps(prompt_data)

        all_findings += await run_analyzer_pass(
            bundle.yara,
            _arguments,
            {"prompt_name": name, "content_type": "arguments"},
            label="YARA",
            failure_log=f'YARA analysis failed on prompt arguments: prompt="{name}"',
        )

    if AnalyzerEnum.LLM in analyzers and bundle.llm:

        def _comprehensive() -> str:
            content = f"Prompt Name: {name}\n"
            content += f"Description: {description}\n"
            if prompt_data.get("arguments"):
                content += (
                    f"Arguments: {json.dumps(prompt_data['arguments'], indent=2)}\n"
                )
            return content

        all_findings += await run_analyzer_pass(
            bundle.llm,
            _comprehensive,
            {"prompt_name": name, "content_type": "comprehensive"},
            label="LLM",
            failure_log=f'LLM analysis failed: prompt="{name}"',
        )
    elif AnalyzerEnum.LLM in analyzers and not bundle.llm:
        _warn_llm_uninitialized(f"prompt '{name}'")

    if AnalyzerEnum.PROMPT_DEFENSE in analyzers and bundle.prompt_defense:
        all_findings += await run_analyzer_pass(
            bundle.prompt_defense,
            description,
            {"tool_name": name, "content_type": "description"},
            label="PromptDefense",
            failure_log=f'Prompt defense analysis failed: prompt="{name}"',
        )

    custom_findings, custom_names = await run_custom_analyzers(
        bundle.custom,
        description,
        {"prompt_name": name, "content_type": "description"},
        http_headers,
        failure_subject=f': prompt="{name}"',
    )
    all_findings += custom_findings

    return PromptScanResult(
        prompt_name=name,
        prompt_description=description,
        status="completed",
        analyzers=_reported_analyzers(analyzers, custom_names),
        findings=all_findings,
    )


async def analyze_instructions(
    bundle: AnalyzerBundle,
    instructions: str,
    server_name: str,
    protocol_version: str,
    analyzers: List[AnalyzerEnum],
    http_headers: Optional[dict] = None,
) -> InstructionsScanResult:
    """Analyze a server's instructions text with the requested analyzers."""
    all_findings: List[Any] = []
    context = {"server_name": server_name, "content_type": "instructions"}

    if AnalyzerEnum.API in analyzers and bundle.api:
        all_findings += await run_analyzer_pass(
            bundle.api,
            instructions,
            dict(context),
            label="API",
            failure_log=f'API analysis failed on instructions: server="{server_name}"',
        )

    if AnalyzerEnum.YARA in analyzers:
        all_findings += await run_analyzer_pass(
            bundle.yara,
            instructions,
            dict(context),
            label="YARA",
            failure_log=f'YARA analysis failed on instructions: server="{server_name}"',
        )

    if AnalyzerEnum.LLM in analyzers and bundle.llm:

        def _comprehensive() -> str:
            content = f"Server Name: {server_name}\n"
            content += f"Protocol Version: {protocol_version}\n"
            content += f"Instructions: {instructions}\n"
            return content

        all_findings += await run_analyzer_pass(
            bundle.llm,
            _comprehensive,
            dict(context),
            label="LLM",
            failure_log=f'LLM analysis failed on instructions: server="{server_name}"',
        )
    elif AnalyzerEnum.LLM in analyzers and not bundle.llm:
        _warn_llm_uninitialized(f"instructions from '{server_name}'")

    if AnalyzerEnum.PROMPT_DEFENSE in analyzers and bundle.prompt_defense:
        all_findings += await run_analyzer_pass(
            bundle.prompt_defense,
            instructions,
            {"tool_name": server_name, "content_type": "instructions"},
            label="PromptDefense",
            failure_log=(
                f'Prompt defense analysis failed on instructions: server="{server_name}"'
            ),
        )

    custom_findings, custom_names = await run_custom_analyzers(
        bundle.custom,
        instructions,
        dict(context),
        http_headers,
        failure_subject=f' on instructions: server="{server_name}"',
    )
    all_findings += custom_findings

    return InstructionsScanResult(
        instructions=instructions,
        server_name=server_name,
        protocol_version=protocol_version,
        status="completed",
        analyzers=_reported_analyzers(analyzers, custom_names),
        findings=all_findings,
    )


def _extract_resource_text(content: str, uri: str, mime_type: str) -> str:
    """Return analyzable text for a resource, unwrapping HTML when possible."""
    if mime_type != "text/html":
        return content
    try:
        from bs4 import BeautifulSoup

        text = BeautifulSoup(content, "html.parser").get_text(separator="\n", strip=True)
        logger.info(f"Extracted text from HTML resource: {uri}")
        return text
    except ImportError:
        logger.warning("BeautifulSoup not installed, analyzing raw HTML content")
    except (ValueError, TypeError) as e:
        logger.warning(f"Error parsing HTML for resource '{uri}': {e}. Using raw content.")
    except Exception as e:
        logger.error(
            f"Unexpected error extracting text from HTML '{uri}': {e}. Using raw content."
        )
    return content


async def analyze_resource(
    bundle: AnalyzerBundle,
    resource_content: str,
    resource_uri: str,
    resource_name: str,
    resource_description: str,
    resource_mime_type: str,
    analyzers: List[AnalyzerEnum],
    http_headers: Optional[dict] = None,
) -> ResourceScanResult:
    """Analyze a single MCP resource. Only API and LLM apply to resources."""
    all_findings: List[Any] = []
    analysis_content = _extract_resource_text(
        resource_content, resource_uri, resource_mime_type
    )
    context = {
        "resource_uri": resource_uri,
        "resource_name": resource_name,
        "resource_description": resource_description,
        "mime_type": resource_mime_type,
    }

    if AnalyzerEnum.API in analyzers and bundle.api:
        all_findings += await run_analyzer_pass(
            bundle.api,
            analysis_content,
            dict(context),
            label="API",
            failure_log=f'API analysis failed on resource: uri="{resource_uri}"',
        )

    if AnalyzerEnum.LLM in analyzers and bundle.llm:

        def _comprehensive() -> str:
            content = f"Resource URI: {resource_uri}\n"
            content += f"Resource Name: {resource_name}\n"
            if resource_description:
                content += f"Description: {resource_description}\n"
            content += f"MIME Type: {resource_mime_type}\n"
            content += f"Content:\n{analysis_content[:2000]}\n"
            return content

        all_findings += await run_analyzer_pass(
            bundle.llm,
            _comprehensive,
            dict(context),
            label="LLM",
            failure_log=f'LLM analysis failed: resource="{resource_uri}"',
        )
    elif AnalyzerEnum.LLM in analyzers and not bundle.llm:
        _warn_llm_uninitialized(f"resource '{resource_uri}'")

    custom_findings, custom_names = await run_custom_analyzers(
        bundle.custom,
        analysis_content,
        dict(context),
        http_headers,
        failure_subject=f': resource="{resource_uri}"',
    )
    all_findings += custom_findings

    applicable = [a for a in analyzers if a in (AnalyzerEnum.API, AnalyzerEnum.LLM)]

    return ResourceScanResult(
        resource_uri=resource_uri,
        resource_name=resource_name,
        resource_mime_type=resource_mime_type,
        status="completed",
        analyzers=applicable + custom_names,
        findings=all_findings,
        # Persist the content the analyzers actually consumed -- post-HTML
        # extraction -- so the meta-analyzer can second-guess their decisions
        # against the same evidence.
        resource_description=resource_description,
        resource_text=analysis_content,
    )
