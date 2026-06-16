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


def test_report_generator_uses_shared_helper() -> None:
    """ReportGenerator must delegate severity rollup to get_highest_severity
    rather than maintaining its own implementation. Guards against the helper
    drifting back into a private duplicate inside report_generator.py.
    """
    import inspect

    from mcpscanner.core import report_generator as rg

    # No private wrapper named _get_highest_severity should live on the class.
    assert not hasattr(rg.ReportGenerator, "_get_highest_severity"), (
        "ReportGenerator._get_highest_severity has been removed; callers "
        "should use mcpscanner.core.result.get_highest_severity directly."
    )

    # And the module should import the shared helper so call sites can use it.
    src = inspect.getsource(rg)
    assert "from .result import get_highest_severity" in src
    assert "get_highest_severity(" in src


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
    concrete_only = ["HIGH", "MEDIUM", "LOW", "INFO", "ERROR", "SAFE"]
    for sev in concrete_only:
        assert get_highest_severity([sev]) != "UNKNOWN"
        assert get_highest_severity([sev, "UNKNOWN"]) != "UNKNOWN"

    assert get_highest_severity([]) == "UNKNOWN"
    assert get_highest_severity(["UNKNOWN", "UNKNOWN"]) == "UNKNOWN"


# -----------------------------------------------------------------------
# ERROR severity (verification-failure) contract tests
# -----------------------------------------------------------------------
#
# ERROR is the sentinel emitted when an analyzer attempted verification
# but the verification path itself failed (e.g. LLM provider unreachable,
# Bedrock model id invalid, throttled past retry). It is semantically
# distinct from UNKNOWN ("not yet analyzed") and from SAFE ("verified
# clean"). The rollup must treat it as concrete (so it displaces
# UNKNOWN), rank it above SAFE (so a tool with both ERROR and SAFE rows
# is reported as ERROR — you cannot claim a tool is clean if any
# function on it was unverified), and rank it below the real triage
# severities INFO/LOW/MEDIUM/HIGH (so a real low-signal finding still
# wins when both are present on the same scope).


@pytest.mark.parametrize(
    "severities,expected",
    [
        # ERROR alone is concrete.
        (["ERROR"], "ERROR"),
        # ERROR displaces UNKNOWN, just like every other concrete severity.
        (["ERROR", "UNKNOWN"], "ERROR"),
        (["UNKNOWN", "ERROR"], "ERROR"),
        # ERROR ranks above SAFE: a tool with both unverified and clean
        # functions is NOT clean.
        (["ERROR", "SAFE"], "ERROR"),
        (["SAFE", "ERROR"], "ERROR"),
        # ERROR ranks below the real triage severities.
        (["ERROR", "INFO"], "INFO"),
        (["ERROR", "LOW"], "LOW"),
        (["ERROR", "MEDIUM"], "MEDIUM"),
        (["ERROR", "HIGH"], "HIGH"),
        # Case-insensitive.
        (["error"], "ERROR"),
        (["error", "safe"], "ERROR"),
        (["error", "high"], "HIGH"),
        # Mixed with UNKNOWN: the concrete ERROR still wins.
        (["UNKNOWN", "ERROR", "UNKNOWN"], "ERROR"),
    ],
)
def test_error_severity_rollup(severities: List[str], expected: str) -> None:
    """Pin the ERROR severity ranking. See module-level comment above."""
    assert get_highest_severity(severities) == expected


def test_error_does_not_collapse_into_unknown() -> None:
    """Regression: prior to the ERROR-not-SAFE PR completion, ERROR was
    not in ``severity_order`` so ``get_highest_severity(["ERROR"])`` would
    fall through to ``return "UNKNOWN"``. That collapse erased the entire
    point of emitting ERROR severity rows from BehavioralCodeAnalyzer at
    the artifact-format layer.
    """
    assert get_highest_severity(["ERROR"]) == "ERROR"
    # And any list that contains ERROR plus only UNKNOWNs must never
    # roll up as UNKNOWN — that would silently re-bucket verification
    # failures alongside "analyzer didn't run".
    assert get_highest_severity(["ERROR", "UNKNOWN"]) == "ERROR"
    assert get_highest_severity(["UNKNOWN", "ERROR"]) == "ERROR"


def test_error_does_not_get_reported_as_clean() -> None:
    """Regression: ERROR must NEVER roll up as SAFE. A tool with both an
    unverified function (ERROR) and a clean function (SAFE) cannot be
    advertised to operators as a clean tool — you cannot certify what
    you didn't verify. This test pins that invariant directly.
    """
    rollup = get_highest_severity(["ERROR", "SAFE"])
    assert rollup != "SAFE", (
        f"[ERROR, SAFE] rolled up as {rollup!r}; this would let a partial "
        "verification failure masquerade as a clean tool — re-introducing "
        "the original silent-failure bug at the per-tool aggregation level."
    )
    assert rollup == "ERROR"


# -----------------------------------------------------------------------
# process_scan_results / report_generator counts include ERROR
# -----------------------------------------------------------------------


def test_process_scan_results_counts_error_findings() -> None:
    """``process_scan_results`` must include ERROR in its severity_counts
    dict so verification failures are countable in summary stats. The
    historical bug was the ``if severity in severity_counts`` guard
    dropping ERROR entries on the floor.
    """
    from mcpscanner.config.constants import SeverityLevel  # noqa: F401
    from mcpscanner.core.analyzers.base import SecurityFinding
    from mcpscanner.core.result import ToolScanResult, process_scan_results

    findings = [
        SecurityFinding(
            severity="ERROR",
            summary="LLM verification unavailable for echo: RuntimeError: simulated",
            threat_category="",
            analyzer="Behavioral",
            details={"function_name": "echo", "llm_unavailable": True},
        ),
        SecurityFinding(
            severity="HIGH",
            summary="real mismatch",
            threat_category="DATA EXFILTRATION",
            analyzer="Behavioral",
            details={"function_name": "leaky"},
        ),
    ]
    result = ToolScanResult(
        tool_name="t1",
        tool_description="d",
        status="completed",
        analyzers=["Behavioral"],
        findings=findings,
    )
    summary = process_scan_results([result])

    counts = summary["severity_counts"]
    assert "ERROR" in counts, (
        "process_scan_results.severity_counts must enumerate ERROR; "
        "missing ERROR key drops verification-failure counts on the "
        "floor via the `if severity in severity_counts` guard."
    )
    assert counts["ERROR"] == 1
    assert counts["HIGH"] == 1


def test_report_generator_statistics_count_error() -> None:
    """``ReportGenerator.get_statistics`` exposes severity_counts to
    callers building dashboards / alerts. Missing ERROR there silently
    drops the count, so we lock the dict shape.
    """
    from mcpscanner.core.report_generator import ReportGenerator

    scan_data = {
        "scan_results": [
            {
                "tool_name": "t1",
                "is_safe": False,
                "findings": {
                    "behavioral_analyzer": {
                        "severity": "ERROR",
                        "total_findings": 1,
                    },
                },
            },
            {
                "tool_name": "t2",
                "is_safe": False,
                "findings": {
                    "behavioral_analyzer": {
                        "severity": "ERROR",
                        "total_findings": 2,
                    },
                },
            },
        ]
    }
    rg = ReportGenerator(scan_data)
    stats = rg.get_statistics()
    counts = stats["severity_counts"]

    assert "ERROR" in counts, (
        "ReportGenerator.get_statistics severity_counts must include "
        "ERROR; otherwise verification-failure rows are silently dropped "
        "from the dashboard rollup."
    )
    assert counts["ERROR"] == 2


def test_report_generator_markdown_renders_error_section() -> None:
    """The grouped markdown report iterates a hardcoded ``severity_order``
    list. ERROR must be in that list, otherwise its rows are silently
    skipped in the rendered output and operators reading the markdown
    artifact see no indication that the LLM was unreachable.
    """
    from mcpscanner.core.models import SeverityFilter
    from mcpscanner.core.report_generator import ReportGenerator

    results = [
        {
            "tool_name": "ht",
            "is_safe": False,
            "findings": {
                "behavioral_analyzer": {
                    "severity": "HIGH",
                    "threat_summary": "real mismatch",
                    "total_findings": 1,
                }
            },
        },
        {
            "tool_name": "et",
            "is_safe": False,
            "findings": {
                "behavioral_analyzer": {
                    "severity": "ERROR",
                    "threat_summary": "LLM unavailable",
                    "total_findings": 1,
                }
            },
        },
    ]
    rg = ReportGenerator({"scan_results": results})
    output = rg._format_by_severity(results, SeverityFilter.ALL)  # type: ignore[attr-defined]

    assert "ERROR SEVERITY" in output, (
        "Markdown report must surface an ERROR SEVERITY section; missing "
        "it means verification-failure rows are invisible to operators "
        "reading findings.md."
    )
    assert "et" in output, "tool name from the ERROR group must be rendered"
    # ERROR section has to render AFTER the security buckets so operators
    # triage real risk first; pin that ordering.
    assert output.index("HIGH SEVERITY") < output.index("ERROR SEVERITY")
    assert "LLM unavailable" in output, (
        "threat_summary from the ERROR finding must reach the markdown "
        "output so operators can see what failed without opening the "
        "raw JSON artifact"
    )
