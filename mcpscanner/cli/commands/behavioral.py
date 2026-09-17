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

"""``behavioral``: analyze local source for docstring/behavior mismatches."""

import json
from typing import Any, Optional

from mcpscanner.core.models import AnalyzerEnum

from ..config import _build_config
from ..context import CommandContext
from ..results import _build_behavioral_results


async def run(ctx: CommandContext) -> Optional[Any]:
    """Analyze a source tree and report tools whose behavior contradicts docs."""
    args = ctx.args

    cfg = _build_config([AnalyzerEnum.BEHAVIORAL])

    from mcpscanner.core.analyzers.behavioral import BehavioralCodeAnalyzer

    analyzer = BehavioralCodeAnalyzer(cfg)

    source_path = args.source_path

    # Analyze the source file
    findings = await analyzer.analyze(source_path, context={"file_path": source_path})

    # Build a result entry for every analyzed MCP tool — including
    # tools with no findings (is_safe=True). This ensures the scan
    # output enumerates ALL tools detected during the scan, not only
    # tools flagged as malicious.
    results = _build_behavioral_results(analyzer, findings, source_path)

    # Filter out VULNERABILITY findings — only surface THREATS — while
    # always keeping safe results so every analyzed tool remains visible.
    # Applies to both formatted and ``--raw`` JSON output.
    filtered_results = []
    for result in results:
        if result.get("is_safe", False):
            filtered_results.append(result)
            continue

        analyzer_data = result.get("findings", {}).get("behavioral_analyzer", {})
        classification = (
            analyzer_data.get("threat_vulnerability_classification") or ""
        ).upper()

        if classification == "THREAT":
            filtered_results.append(result)

    results = filtered_results

    # Save output if requested
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        if args.verbose:
            print(f"Results saved to {args.output}")
    return results
