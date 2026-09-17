# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Golden-file coverage of the SDK JSON serializer.

format_results_as_json is a published output shape -- SDK consumers index
into ``findings.<analyzer>`` directly -- but only its meta-analysis block
was covered. The grid in result_json_grid.py exercises the four result
types, the unknown-type skip, analyzer aggregation, taxonomy and
classification passthrough, and the UNKNOWN-severity path.

To regenerate after a deliberate change, re-run the recording snippet in
this module's git history and review the diff: a changed field means SDK
consumers see something different.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from mcpscanner.core.result import format_results_as_json

from tests.result_json_grid import CASES

BASELINE = json.loads(
    (pathlib.Path(__file__).parent / "result_json_baseline.json").read_text()
)


@pytest.mark.parametrize("name,results", CASES, ids=[c[0] for c in CASES])
def test_serialized_shape_matches_baseline(name, results):
    assert json.loads(format_results_as_json(results)) == BASELINE[name]


@pytest.mark.parametrize("name,results", CASES, ids=[c[0] for c in CASES])
def test_every_analyzer_block_is_always_present(name, results):
    """Consumers index findings.<analyzer> without checking; keep that true."""
    payload = json.loads(format_results_as_json(results))

    for entry in payload["scan_results"]:
        assert set(entry["findings"]) == {
            "api_analyzer",
            "yara_analyzer",
            "llm_analyzer",
        }
