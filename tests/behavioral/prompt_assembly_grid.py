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

"""A grid of _assemble_prompt inputs covering every budget path.

Shared by the characterization test and by the one-off script that recorded
the baseline, so both drive the assembler with exactly the same cases.
"""

from mcpscanner.core.analyzers.behavioral.alignment import (
    alignment_prompt_builder as apb,
)

RESPONSE_SCHEMA = apb._RESPONSE_FORMAT_MARKER + (
    '\n{"aligned": true, "confidence": 0.0, "reasoning": ""}\n'
)


def template(guidance_chars: int, *, pinned: bool = True) -> str:
    body = "GUIDANCE " * (guidance_chars // 9 + 1)
    return body[:guidance_chars] + (RESPONSE_SCHEMA if pinned else "")


def analysis(
    main_chars: int, *, graph: int = 0, dataflow: int = 0, sinks: int = 0
) -> str:
    parts = ["MAIN body line.\n" * (main_chars // 16 + 1)]
    parts[0] = parts[0][:main_chars]
    if graph:
        parts.append(apb._GRAPH_EVIDENCE_HEADER + ("g" * graph) + "\n")
    if dataflow:
        parts.append(apb._CLASSIC_DATAFLOW_HEADER + ("d" * dataflow) + "\n")
    if sinks:
        parts.append(apb._SINK_HINTS_HEADER + ("s" * sinks) + "\n")
    return "".join(parts)


# (case id, kwargs for _assemble_prompt, budget override or None)
CASES = []


def _case(name, *, budget=None, **kwargs):
    kwargs.setdefault("start_tag", "<UNTRUSTED_INPUT>")
    kwargs.setdefault("end_tag", "</UNTRUSTED_INPUT>")
    kwargs.setdefault("log_label", name)
    CASES.append((name, kwargs, budget))


# Everything fits comfortably.
_case("tiny_fits", template=template(200), analysis_content=analysis(200))
_case(
    "tiny_fits_no_relocate",
    template=template(200),
    analysis_content=analysis(200),
    relocate_preserved=False,
)
_case(
    "tiny_fits_prefix",
    template=template(200),
    analysis_content=analysis(200),
    prefix="P:",
)
_case(
    "no_pinned_schema",
    template=template(200, pinned=False),
    analysis_content=analysis(200),
)

# Analysis must shrink; graph evidence must survive.
for budget in (1500, 3000, 8000):
    _case(
        f"analysis_over_{budget}",
        budget=budget,
        template=template(400),
        analysis_content=analysis(20000, graph=600),
    )
    _case(
        f"analysis_over_{budget}_no_relocate",
        budget=budget,
        template=template(400),
        analysis_content=analysis(20000, graph=600),
        relocate_preserved=False,
    )

# Guidance must shrink too.
for budget in (900, 2000, 5000):
    _case(
        f"guidance_over_{budget}",
        budget=budget,
        template=template(9000),
        analysis_content=analysis(9000, graph=400, sinks=300),
    )
    _case(
        f"guidance_over_{budget}_no_relocate",
        budget=budget,
        template=template(9000),
        analysis_content=analysis(9000, graph=400, sinks=300),
        relocate_preserved=False,
    )

# Preserved sections alone blow the budget, forcing the capping path.
for budget in (600, 1200, 4000):
    _case(
        f"preserved_heavy_{budget}",
        budget=budget,
        template=template(800),
        analysis_content=analysis(3000, graph=5000, dataflow=4000, sinks=3000),
    )

# Budgets so small the frame itself barely fits.
for budget in (0, 40, 120, 300):
    _case(
        f"degenerate_{budget}",
        budget=budget,
        template=template(3000),
        analysis_content=analysis(3000, graph=500),
    )
    _case(
        f"degenerate_{budget}_no_relocate",
        budget=budget,
        template=template(3000),
        analysis_content=analysis(3000, graph=500),
        relocate_preserved=False,
    )

# Empty and whitespace inputs.
_case("empty_analysis", template=template(300), analysis_content="")
_case("empty_template", template="", analysis_content=analysis(500, graph=200))
_case("both_empty", template="", analysis_content="")
_case(
    "only_preserved",
    budget=2000,
    template=template(300),
    analysis_content=analysis(0, graph=4000, sinks=2000),
)


def run_case(builder, kwargs, budget, monkeypatch_setattr):
    """Assemble one case, applying a budget override when the case has one."""
    if budget is not None:
        monkeypatch_setattr(
            apb.MCPScannerConstants, "ALIGNMENT_MAX_PROMPT_CHARS", budget
        )
    return builder._assemble_prompt(**kwargs)
