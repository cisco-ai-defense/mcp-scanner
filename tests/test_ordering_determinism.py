# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Order-preserving dedupe, and the report fields that depend on it.

Python randomizes string hashing per process, so `list(set(xs))` returns a
different order in different runs. Two places cared: report fields, which
then cannot be diffed between scans of the same server, and
`list(set(xs))[:50]` truncations, which silently change *which* items
survive to reach an LLM prompt.
"""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap

from mcpscanner.utils.ordering import dedupe, union


class TestDedupe:
    def test_keeps_first_seen_order(self):
        assert dedupe(["b", "a", "b", "c", "a"]) == ["b", "a", "c"]

    def test_empty(self):
        assert dedupe([]) == []

    def test_no_duplicates_is_identity(self):
        assert dedupe(["x", "y", "z"]) == ["x", "y", "z"]

    def test_accepts_any_iterable(self):
        assert dedupe(x % 3 for x in range(7)) == [0, 1, 2]

    def test_truncation_keeps_the_first_n_distinct(self):
        # The property the [:50] call sites rely on: which items survive is
        # decided by source order, not by hash order.
        assert dedupe(["a", "a", "b", "c", "d"])[:3] == ["a", "b", "c"]


class TestUnion:
    def test_concatenates_then_dedupes(self):
        assert union(["a", "b"], ["b", "c"]) == ["a", "b", "c"]

    def test_is_not_commutative_in_order(self):
        assert union(["b"], ["a"]) == ["b", "a"]
        assert union(["a"], ["b"]) == ["a", "b"]

    def test_handles_no_arguments(self):
        assert union() == []


def _run_in_fresh_process(code: str) -> str:
    out = subprocess.run(
        [sys.executable, "-c", textwrap.dedent(code)],
        capture_output=True,
        text=True,
        check=True,
    )
    return out.stdout.strip()


def test_report_threat_names_are_stable_across_processes():
    """Same findings, separate interpreters, identical JSON.

    Run in subprocesses on purpose: hash randomization is fixed for the
    life of a process, so this cannot be reproduced in-process.
    """
    code = """
        import json
        from mcpscanner.core.analyzers.base import SecurityFinding
        from mcpscanner.core.result import ToolScanResult, format_results_as_json

        findings = [
            SecurityFinding(
                severity="HIGH",
                summary="s",
                analyzer="YARA",
                threat_category="T",
                details={"threat_type": t},
            )
            for t in ("exfil", "inject", "persist", "escalate", "evade")
        ]
        result = ToolScanResult(
            tool_name="t",
            tool_description="d",
            status="completed",
            analyzers=["API", "YARA", "LLM"],
            findings=findings,
        )
        payload = json.loads(format_results_as_json([result]))
        print(json.dumps(payload["scan_results"][0]["findings"]["yara_analyzer"]["threat_names"]))
    """
    runs = {_run_in_fresh_process(code) for _ in range(5)}

    assert len(runs) == 1, f"threat_names ordering varied across runs: {runs}"
    assert json.loads(runs.pop()) == [
        "exfil",
        "inject",
        "persist",
        "escalate",
        "evade",
    ]
