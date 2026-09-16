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

"""``static``: scan tool/prompt/resource definitions from local JSON files."""

import sys
from typing import Any, Optional

from mcpscanner import Scanner
from mcpscanner.core.analyzers.api_analyzer import ApiAnalyzer
from mcpscanner.core.analyzers.llm_analyzer import LLMAnalyzer
from mcpscanner.core.analyzers.static_analyzer import StaticAnalyzer
from mcpscanner.core.analyzers.yara_analyzer import YaraAnalyzer
from mcpscanner.core.models import AnalyzerEnum
from mcpscanner.core.report_generator import results_to_json

from ..config import _build_config
from ..context import CommandContext


async def run(ctx: CommandContext) -> Optional[Any]:
    """Scan definitions read from files rather than from a live server."""
    args = ctx.args
    selected_analyzers = ctx.analyzers

    cfg = _build_config(selected_analyzers)

    # Build analyzer list
    analyzers = []
    if AnalyzerEnum.YARA in selected_analyzers:
        analyzers.append(YaraAnalyzer(rules_dir=args.rules_path))
    if AnalyzerEnum.LLM in selected_analyzers:
        if cfg.llm_provider_api_key:
            analyzers.append(LLMAnalyzer(cfg))
        else:
            print(
                "Warning: LLM analyzer requested but MCP_SCANNER_LLM_API_KEY not set",
                file=sys.stderr,
            )
    if AnalyzerEnum.API in selected_analyzers:
        if cfg.api_key:
            analyzers.append(ApiAnalyzer(cfg))
        else:
            print(
                "Warning: API analyzer requested but MCP_SCANNER_API_KEY not set",
                file=sys.stderr,
            )

    if not analyzers:
        print(
            "Error: No analyzers available. Set appropriate API keys or use YARA.",
            file=sys.stderr,
        )
        sys.exit(1)

    static = StaticAnalyzer(analyzers=analyzers, config=cfg)
    all_results = []

    # Get files to scan from subcommand args
    tools_file = getattr(args, "tools", None)
    prompts_file = getattr(args, "prompts", None)
    resources_file = getattr(args, "resources", None)

    if not (tools_file or prompts_file or resources_file):
        print("Error: No files specified for static scanning", file=sys.stderr)
        print(
            "Usage: mcp-scanner static --tools FILE and/or --prompts FILE and/or --resources FILE",
            file=sys.stderr,
        )
        sys.exit(1)

    # Scan tools
    if tools_file:
        tools_results = await static.scan_tools_file(tools_file)
        # Convert to ToolScanResult format
        from mcpscanner.core.result import ToolScanResult

        for r in tools_results:
            tool_result = ToolScanResult(
                tool_name=r["tool_name"],
                tool_description=r.get("tool_description", ""),
                status=r["status"],
                analyzers=r.get("analyzers", []),
                findings=r["findings"],
            )
            all_results.append(tool_result)

    # Scan prompts
    if prompts_file:
        prompts_results = await static.scan_prompts_file(prompts_file)
        from mcpscanner.core.result import PromptScanResult

        for r in prompts_results:
            prompt_result = PromptScanResult(
                prompt_name=r["prompt_name"],
                prompt_description=r.get("prompt_description", ""),
                status=r["status"],
                analyzers=r.get("analyzers", []),
                findings=r["findings"],
            )
            all_results.append(prompt_result)

    # Scan resources
    if resources_file:
        mime_types = getattr(args, "mime_types", "text/plain,text/html")
        mime_types_list = (
            mime_types.split(",") if mime_types else ["text/plain", "text/html"]
        )
        resources_results = await static.scan_resources_file(
            resources_file, allowed_mime_types=mime_types_list
        )
        from mcpscanner.core.result import ResourceScanResult

        for r in resources_results:
            resource_result = ResourceScanResult(
                resource_uri=r["resource_uri"],
                resource_name=r["resource_name"],
                resource_mime_type=r.get("resource_mime_type", "unknown"),
                status=r["status"],
                analyzers=r.get("analyzers", []),
                findings=r["findings"],
                # Thread the description / text the static analyzer
                # consumed so ``--enable-meta`` can second-guess
                # findings against the same evidence the primary
                # pass saw. Without these the meta-analyzer falls
                # back to ``"N/A"`` for description and FP triage
                # on file-based resources is unsupervised.
                resource_description=r.get("resource_description", ""),
                resource_text=r.get("resource_text", ""),
            )
            all_results.append(resource_result)

    # P0-5 fix: also accept Bedrock-via-AWS-credentials. Previously
    # this gate only honoured ``llm_provider_api_key`` and silently
    # no-op'd on the IAM-only Lambda flow this branch was built for.
    # Mirror Scanner.__init__'s ``(api_key or is_bedrock)`` rule so
    # ``--enable-meta`` with ``MCP_SCANNER_LLM_MODEL=bedrock/...`` and
    # an AWS profile works end-to-end.
    _meta_is_bedrock = bool(
        cfg.llm_model and "bedrock/" in cfg.llm_model
    )
    if AnalyzerEnum.META in selected_analyzers and (
        cfg.llm_provider_api_key or _meta_is_bedrock
    ):
        # P1-6 fix: route through Scanner.apply_meta_to_results
        # rather than reimplementing per-result meta-analysis here.
        # The previous inline loop had drifted from the Scanner
        # helpers and produced two real bugs (P0-4 silently dropped
        # resource/instructions enrichment, P0-5 silently no-op'd
        # on the IAM-only Bedrock flow). One source of truth.
        #
        # M2 fix: use ``for_meta_only`` so the static path doesn't
        # pay the cost of constructing every primary analyzer
        # (Yara compilation, ApiAnalyzer endpoint validation,
        # Behavioral / VT / Readiness / PromptDefense) just to
        # invoke a single LLM-backed entrypoint. ``rules_dir``
        # is intentionally dropped here — the meta-only path
        # never touches Yara.
        meta_scanner = Scanner.for_meta_only(cfg)
        all_results = await meta_scanner.apply_meta_to_results(
            all_results, [AnalyzerEnum.META]
        )

    results = await results_to_json(all_results)
    return results
