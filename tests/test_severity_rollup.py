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

"""Severity rollup contract tests.

Locks in the model that ``UNKNOWN`` is the pre-analysis default and is
displaced by any concrete severity (``HIGH``/``MEDIUM``/``LOW``/``INFO``/
``SAFE``). After analysis the rollup is therefore always either ``SAFE``,
one of the unsafe severities, or ``UNKNOWN`` (if no analyzer produced a
concrete result).
"""

from typing import List

import pytest

from mcpscanner.core.report_generator import ReportGenerator
from mcpscanner.core.result import get_highest_severity


@pytest.mark.parametrize(
    "severities,expected",
    [
        # Pre-analysis: nothing to roll up -> UNKNOWN.
        ([], "UNKNOWN"),
        # All analyzers failed / not run -> still UNKNOWN.
        (["UNKNOWN"], "UNKNOWN"),
        (["UNKNOWN", "UNKNOWN"], "UNKNOWN"),
        # A single concrete result wins.
        (["SAFE"], "SAFE"),
        (["INFO"], "INFO"),
        (["LOW"], "LOW"),
        (["MEDIUM"], "MEDIUM"),
        (["HIGH"], "HIGH"),
        # UNKNOWN is displaced by ANY concrete severity, including SAFE.
        (["SAFE", "UNKNOWN"], "SAFE"),
        (["INFO", "UNKNOWN"], "INFO"),
        (["LOW", "UNKNOWN"], "LOW"),
        (["MEDIUM", "UNKNOWN"], "MEDIUM"),
        (["HIGH", "UNKNOWN"], "HIGH"),
        # Highest concrete severity wins.
        (["INFO", "SAFE"], "INFO"),
        (["INFO", "LOW"], "LOW"),
        (["SAFE", "MEDIUM"], "MEDIUM"),
        (["LOW", "MEDIUM", "HIGH"], "HIGH"),
        # Mixed concrete + UNKNOWN.
        (["LOW", "MEDIUM", "UNKNOWN"], "MEDIUM"),
        (["HIGH", "UNKNOWN", "SAFE"], "HIGH"),
        # Case-insensitive input.
        (["safe", "high"], "HIGH"),
        (["medium"], "MEDIUM"),
        # Unknown labels are ignored as if they weren't there.
        (["BOGUS"], "UNKNOWN"),
        (["BOGUS", "LOW"], "LOW"),
    ],
)
def test_get_highest_severity_rollup(severities: List[str], expected: str) -> None:
    assert get_highest_severity(severities) == expected


def test_get_highest_severity_ignores_falsy_entries() -> None:
    """Empty / None entries should be skipped, not treated as concrete."""
    assert get_highest_severity(["", None, "UNKNOWN"]) == "UNKNOWN"  # type: ignore[list-item]
    assert get_highest_severity(["", None, "MEDIUM"]) == "MEDIUM"  # type: ignore[list-item]


class _ReportGeneratorStub(ReportGenerator):
    """Bypass ReportGenerator.__init__ — we only need the helper method."""

    def __init__(self) -> None:  # noqa: D401 - intentional no-op
        pass


def test_report_generator_helper_delegates_to_shared_logic() -> None:
    """ReportGenerator._get_highest_severity must mirror get_highest_severity."""
    stub = _ReportGeneratorStub()

    cases = [
        [],
        ["UNKNOWN"],
        ["SAFE", "UNKNOWN"],
        ["LOW", "UNKNOWN"],
        ["MEDIUM", "UNKNOWN"],
        ["HIGH", "UNKNOWN"],
        ["INFO", "LOW", "MEDIUM", "HIGH"],
    ]
    for severities in cases:
        assert stub._get_highest_severity(severities) == get_highest_severity(
            severities
        )


def test_unknown_does_not_outrank_concrete_severities() -> None:
    """Regression: UNKNOWN used to be ranked above MEDIUM/LOW. It must not."""
    # If even one analyzer produced a concrete severity, UNKNOWN must lose.
    assert get_highest_severity(["UNKNOWN", "LOW"]) == "LOW"
    assert get_highest_severity(["UNKNOWN", "MEDIUM"]) == "MEDIUM"
    assert get_highest_severity(["UNKNOWN", "SAFE"]) == "SAFE"
    # And HIGH still wins over everything.
    assert get_highest_severity(["UNKNOWN", "HIGH"]) == "HIGH"


def test_post_analysis_rollup_is_never_unknown_when_anything_concrete() -> None:
    """Invariant: post-analysis rollup is SAFE/UNSAFE iff at least one
    analyzer produced a concrete severity. Only fully-unknown input rolls
    up to UNKNOWN.
    """
    concrete_only = ["HIGH", "MEDIUM", "LOW", "INFO", "SAFE"]
    for sev in concrete_only:
        assert get_highest_severity([sev]) != "UNKNOWN"
        assert get_highest_severity([sev, "UNKNOWN"]) != "UNKNOWN"

    assert get_highest_severity([]) == "UNKNOWN"
    assert get_highest_severity(["UNKNOWN", "UNKNOWN"]) == "UNKNOWN"
