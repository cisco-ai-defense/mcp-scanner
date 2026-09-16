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

"""Meta-analysis over already-produced scan results.

``Scanner`` carried four copies of the same routine -- one per entity type --
that built an entity context, called the meta-analyzer, split findings into
kept and dropped, and rebuilt the result. The copies had already drifted:
resources gained budgeted content snippets and instructions gained the
``meta_filtered_findings`` reset several review rounds after tools and prompts
did, and each drift was a separate bug.

Here the four differ only in a :class:`MetaEntitySpec`: how to describe the
entity to the analyzer, how to rebuild its result type, and what to call it in
an error log. Everything else -- concurrency, ordering, the stale-audit reset,
the never-drop-on-failure guarantee -- is written once.
"""

import asyncio
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Sequence

from ..utils.logging_config import get_logger
from .analyzers.meta_analyzer import apply_meta_analysis
from .result import (
    InstructionsScanResult,
    PromptScanResult,
    ResourceScanResult,
    ScanResult,
    ToolScanResult,
)

logger = get_logger(__name__)

# Cap on concurrent LLM round-trips. With this cap a 30-tool server completes
# in ~30/8 = 4 sequential waves instead of 30 sequential round-trips, while
# staying well inside typical Bedrock / Azure OpenAI rate-limit budgets.
DEFAULT_META_CONCURRENCY = 8

# Combined character cap for the description + content snippet handed to the
# meta-analyzer. ~8 KB stays well inside any modern LLM's per-call budget
# while preserving enough context for false-positive triage.
DEFAULT_DESCRIPTION_BUDGET = 8000


def build_instructions_description(
    result: InstructionsScanResult, budget: int = DEFAULT_DESCRIPTION_BUDGET
) -> str:
    """Synthesize a description string for instructions meta-analysis.

    Returns an empty string when ``result.instructions`` is falsy; otherwise
    the full text up to ``budget`` bytes with a clear truncation marker.
    """
    text = (getattr(result, "instructions", "") or "").strip()
    if not text:
        return ""
    if len(text) <= budget:
        return text
    elided = len(text) - budget
    return text[:budget] + f"... [instructions truncated, {elided} bytes elided]"


def build_resource_description(
    result: ResourceScanResult, budget: int = DEFAULT_DESCRIPTION_BUDGET
) -> str:
    """Combine a resource's MCP description with a budgeted content snippet.

    Without the content the meta-analyzer is asked to second-guess resource
    findings from ``name + uri + mime_type`` alone.

    Returns:
        A string of the form ``"<description>\\n\\n--- Content (first N chars)
        ---\\n<text>[truncated, X bytes]"``, or ``"N/A"`` if both are empty.
    """
    description = (getattr(result, "resource_description", "") or "").strip()
    text = (getattr(result, "resource_text", "") or "").strip()

    if not description and not text:
        return "N/A"

    # Reserve up to half the budget for the description; in practice the
    # description is short (<=500 chars) so almost all of the budget ends up
    # available for content. Content needs a 256-char floor to be useful for
    # triage, so past that point the description is what shrinks.
    desc_budget = min(len(description), budget // 2) if description else 0
    text_budget = max(budget - desc_budget, 256) if text else 0

    parts = []
    if description:
        if len(description) > desc_budget:
            parts.append(
                description[:desc_budget]
                + f"... [description truncated, {len(description) - desc_budget} bytes elided]"
            )
        else:
            parts.append(description)

    if text:
        text_total = len(text)
        if text_total > text_budget:
            snippet = (
                text[:text_budget]
                + f"... [content truncated, {text_total - text_budget} bytes elided]"
            )
        else:
            snippet = text
        parts.append(f"--- Content (first {min(text_total, text_budget)} chars) ---\n{snippet}")

    return "\n\n".join(parts)


@dataclass(frozen=True)
class MetaEntitySpec:
    """Everything that differs between entity types during meta-analysis."""

    kind: str
    label: Callable[[Any], str]
    context: Callable[[Any], Dict[str, Any]]
    rebuild: Callable[[Any, List[Any]], ScanResult]


def _tool_context(result: ToolScanResult) -> Dict[str, Any]:
    return {
        "type": "tool",
        "name": result.tool_name,
        "description": result.tool_description,
    }


def _rebuild_tool(result: ToolScanResult, kept: List[Any]) -> ToolScanResult:
    return ToolScanResult(
        tool_name=result.tool_name,
        tool_description=result.tool_description,
        status=result.status,
        analyzers=result.analyzers,
        findings=kept,
        server_source=result.server_source,
        server_name=result.server_name,
    )


def _prompt_context(result: PromptScanResult) -> Dict[str, Any]:
    return {
        "type": "prompt",
        "name": result.prompt_name,
        "description": result.prompt_description,
    }


def _rebuild_prompt(result: PromptScanResult, kept: List[Any]) -> PromptScanResult:
    return PromptScanResult(
        prompt_name=result.prompt_name,
        prompt_description=result.prompt_description,
        status=result.status,
        analyzers=result.analyzers,
        findings=kept,
        server_source=result.server_source,
        server_name=result.server_name,
    )


def _resource_context(result: ResourceScanResult) -> Dict[str, Any]:
    return {
        "type": "resource",
        "name": result.resource_name,
        "uri": result.resource_uri,
        "mime_type": result.resource_mime_type,
        "description": build_resource_description(result),
    }


def _rebuild_resource(result: ResourceScanResult, kept: List[Any]) -> ResourceScanResult:
    return ResourceScanResult(
        resource_uri=result.resource_uri,
        resource_name=result.resource_name,
        resource_mime_type=result.resource_mime_type,
        status=result.status,
        analyzers=result.analyzers,
        findings=kept,
        server_source=result.server_source,
        server_name=result.server_name,
        # Preserve the evidence the primary analyzers consumed; dropping it
        # would mean every meta-enabled run silently zeroed these fields.
        resource_description=getattr(result, "resource_description", "") or "",
        resource_text=getattr(result, "resource_text", "") or "",
    )


def _instructions_context(result: InstructionsScanResult) -> Dict[str, Any]:
    return {
        "type": "instructions",
        "name": result.server_name,
        "description": build_instructions_description(result),
    }


def _rebuild_instructions(
    result: InstructionsScanResult, kept: List[Any]
) -> InstructionsScanResult:
    return InstructionsScanResult(
        instructions=result.instructions,
        server_name=result.server_name,
        protocol_version=result.protocol_version,
        status=result.status,
        analyzers=result.analyzers,
        findings=kept,
        server_source=result.server_source,
    )


TOOL_SPEC = MetaEntitySpec(
    kind="tool",
    label=lambda r: f'tool "{r.tool_name}"',
    context=_tool_context,
    rebuild=_rebuild_tool,
)

PROMPT_SPEC = MetaEntitySpec(
    kind="prompt",
    label=lambda r: f'prompt "{r.prompt_name}"',
    context=_prompt_context,
    rebuild=_rebuild_prompt,
)

RESOURCE_SPEC = MetaEntitySpec(
    kind="resource",
    label=lambda r: f'resource "{r.resource_uri}"',
    context=_resource_context,
    rebuild=_rebuild_resource,
)

INSTRUCTIONS_SPEC = MetaEntitySpec(
    kind="instructions",
    label=lambda r: f'instructions from "{r.server_name}"',
    context=_instructions_context,
    rebuild=_rebuild_instructions,
)

SPEC_BY_RESULT_TYPE = {
    ToolScanResult: TOOL_SPEC,
    PromptScanResult: PROMPT_SPEC,
    ResourceScanResult: RESOURCE_SPEC,
    InstructionsScanResult: INSTRUCTIONS_SPEC,
}


def spec_for(result: ScanResult) -> Optional[MetaEntitySpec]:
    """Return the spec for ``result``'s type, or ``None`` if unrecognized."""
    for result_type, spec in SPEC_BY_RESULT_TYPE.items():
        if isinstance(result, result_type):
            return spec
    return None


class MetaAnalysisRunner:
    """Runs meta-analysis over scan results with bounded concurrency.

    Constructed per call from the scanner's current ``_meta_analyzer``, which
    callers are free to swap after construction.
    """

    def __init__(self, meta_analyzer: Any, concurrency: int = DEFAULT_META_CONCURRENCY):
        self._meta_analyzer = meta_analyzer
        self._concurrency = concurrency

    @property
    def enabled(self) -> bool:
        return self._meta_analyzer is not None

    async def analyze_one(
        self,
        result: ScanResult,
        spec: MetaEntitySpec,
        sem: Optional[asyncio.Semaphore] = None,
    ) -> ScanResult:
        """Meta-analyze a single result, returning the original on any failure.

        Every exit path clears ``meta_filtered_findings`` on the original.
        ``apply_meta_to_results`` invites repeated invocation, and without the
        reset a second pass would leak the prior call's audit list into the new
        response -- claiming findings were filtered when in fact none were.
        """
        if not result.findings:
            result.meta_filtered_findings = []
            return result

        analyzers_used = list({f.analyzer for f in result.findings})
        sem = sem if sem is not None else asyncio.Semaphore(self._concurrency)

        async with sem:
            try:
                meta_result = await self._meta_analyzer.analyze_findings(
                    findings=result.findings,
                    analyzers_used=analyzers_used,
                    entity_context=spec.context(result),
                )
                kept, dropped = apply_meta_analysis(result.findings, meta_result)
                enriched = spec.rebuild(result, kept)
                enriched.meta_filtered_findings = dropped
                return enriched
            except Exception as e:
                logger.error(f"Meta-analysis failed for {spec.label(result)}: {e}")
                result.meta_filtered_findings = []
                return result

    async def analyze_many(
        self, results: Sequence[ScanResult], spec: MetaEntitySpec
    ) -> List[ScanResult]:
        """Meta-analyze results of one entity type, preserving input order."""
        sem = asyncio.Semaphore(self._concurrency)
        return list(
            await asyncio.gather(*(self.analyze_one(r, spec, sem) for r in results))
        )

    async def analyze_mixed(self, results: Sequence[ScanResult]) -> List[ScanResult]:
        """Meta-analyze a heterogeneous list, dispatching on each result's type.

        Results of an unrecognized subclass pass through untouched rather than
        being silently dropped.
        """
        sem = asyncio.Semaphore(self._concurrency)

        async def _dispatch(result: ScanResult) -> ScanResult:
            spec = spec_for(result)
            if spec is None:
                return result
            return await self.analyze_one(result, spec, sem)

        return list(await asyncio.gather(*(_dispatch(r) for r in results)))
