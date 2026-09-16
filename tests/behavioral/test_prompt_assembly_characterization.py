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

"""Golden-file coverage of the alignment prompt budget arithmetic.

_assemble_prompt decides what to throw away when a prompt will not fit, and
the interesting cases are the ones nobody hits during ordinary development:
budgets smaller than the frame, preserved graph blocks that alone exceed the
cap, guidance and analysis shrinking against each other in a loop. Those
paths are cheap to break silently, so the grid in prompt_assembly_grid.py is
pinned here by output hash.

To regenerate after a deliberate change:

    python -c "
    import hashlib, json, sys; sys.path.insert(0, 'tests/behavioral')
    from mcpscanner.core.analyzers.behavioral.alignment import alignment_prompt_builder as apb
    from mcpscanner.core.analyzers.behavioral.alignment.alignment_prompt_builder import AlignmentPromptBuilder
    import prompt_assembly_grid as grid
    b, orig = {}, apb.MCPScannerConstants.ALIGNMENT_MAX_PROMPT_CHARS
    for name, kw, budget in grid.CASES:
        apb.MCPScannerConstants.ALIGNMENT_MAX_PROMPT_CHARS = orig if budget is None else budget
        out = AlignmentPromptBuilder()._assemble_prompt(**kw)
        b[name] = {'len': len(out), 'sha': hashlib.sha256(out.encode()).hexdigest()}
        apb.MCPScannerConstants.ALIGNMENT_MAX_PROMPT_CHARS = orig
    json.dump(b, open('tests/behavioral/prompt_assembly_baseline.json', 'w'), indent=1, sort_keys=True)
    "

and review the diff: a changed hash means some prompt now keeps or drops
different evidence than it used to.
"""

import hashlib
import json
import pathlib

import pytest

from mcpscanner.core.analyzers.behavioral.alignment import (
    alignment_prompt_builder as apb,
)
from mcpscanner.core.analyzers.behavioral.alignment.alignment_prompt_builder import (
    AlignmentPromptBuilder,
)

from .prompt_assembly_grid import CASES

BASELINE = json.loads(
    (pathlib.Path(__file__).parent / "prompt_assembly_baseline.json").read_text()
)


@pytest.fixture
def builder():
    return AlignmentPromptBuilder()


def assemble(builder, kwargs, budget, monkeypatch):
    if budget is not None:
        monkeypatch.setattr(
            apb.MCPScannerConstants, "ALIGNMENT_MAX_PROMPT_CHARS", budget
        )
    return builder._assemble_prompt(**kwargs)


@pytest.mark.parametrize("name,kwargs,budget", CASES, ids=[c[0] for c in CASES])
def test_assembled_prompt_matches_baseline(name, kwargs, budget, builder, monkeypatch):
    prompt = assemble(builder, kwargs, budget, monkeypatch)

    assert {
        "len": len(prompt),
        "sha": hashlib.sha256(prompt.encode()).hexdigest(),
    } == BASELINE[name]


@pytest.mark.parametrize("name,kwargs,budget", CASES, ids=[c[0] for c in CASES])
def test_graph_evidence_survives_whenever_it_fits(
    name, kwargs, budget, builder, monkeypatch
):
    """Evidence is the last thing given up, but a budget can be too small.

    The assembler reserves room for the preserved sections ahead of
    everything else, so they survive any amount of shrinking. What it cannot
    do is fit them into a budget smaller than they are -- those cases fall
    through to the hard cap, which cuts the string wherever it lands.
    """
    if not kwargs.get("relocate_preserved", True):
        pytest.skip("caller opted out of relocating preserved sections")
    _, preserved = apb._split_preserved_sections(kwargs["analysis_content"])
    if apb._GRAPH_EVIDENCE_HEADER not in preserved:
        pytest.skip("case has no graph evidence to preserve")
    # Room for the preserved text plus the frame and pinned response schema.
    if budget is not None and budget < len(preserved) + 200:
        pytest.skip("budget is smaller than the evidence; hard cap governs")

    prompt = assemble(builder, kwargs, budget, monkeypatch)

    assert apb._GRAPH_EVIDENCE_HEADER.strip() in prompt


@pytest.mark.parametrize("name,kwargs,budget", CASES, ids=[c[0] for c in CASES])
def test_closing_fence_is_never_lost(name, kwargs, budget, builder, monkeypatch):
    # The end tag fences untrusted server text; losing it would let that text
    # run into whatever the model reads next.
    prompt = assemble(builder, kwargs, budget, monkeypatch)

    if budget == 0:
        pytest.skip("a zero budget cannot hold a fence")
    assert kwargs["end_tag"] in prompt or kwargs["end_tag"][-len(prompt) :] == prompt
