# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Scan-result fixtures covering every branch of format_results_as_json.

Shared by the characterization test and the script that recorded its
baseline, so both serialize exactly the same objects.
"""

from mcpscanner.core.analyzers.base import SecurityFinding
from mcpscanner.core.result import (
    InstructionsScanResult,
    PromptScanResult,
    ResourceScanResult,
    ToolScanResult,
)

TAXONOMY = {
    "aitech": "AITech-8.2",
    "aitech_name": "Data Exfiltration",
    "aisubtech": "AISubtech-8.2.3",
}


def finding(
    severity="HIGH",
    summary="something bad",
    analyzer="YARA",
    threat_type="data_exfiltration",
    taxonomy=None,
    classification=None,
):
    details = {}
    if threat_type is not None:
        details["threat_type"] = threat_type
    if classification is not None:
        details["threat_vulnerability_classification"] = classification
    f = SecurityFinding(
        severity=severity,
        summary=summary,
        analyzer=analyzer,
        threat_category="TEST",
        details=details,
    )
    if taxonomy is not None:
        f.mcp_taxonomy = taxonomy
    return f


ANALYZERS = ["API", "YARA", "LLM"]


def tool(findings, **kw):
    return ToolScanResult(
        tool_name="demo_tool",
        tool_description="does a thing",
        status="completed",
        analyzers=ANALYZERS,
        findings=findings,
        **kw,
    )


def prompt(findings):
    return PromptScanResult(
        prompt_name="demo_prompt",
        prompt_description="a prompt",
        status="completed",
        analyzers=ANALYZERS,
        findings=findings,
    )


def resource(findings):
    return ResourceScanResult(
        resource_uri="file://x",
        resource_name="x",
        resource_mime_type="text/plain",
        status="completed",
        analyzers=ANALYZERS,
        findings=findings,
    )


def instructions(findings):
    return InstructionsScanResult(
        instructions="be helpful",
        server_name="srv",
        protocol_version="2025-06-18",
        status="completed",
        analyzers=ANALYZERS,
        findings=findings,
    )


class _Unknown:
    """Not one of the four serializable result types; must be skipped."""

    findings = []


def _with_meta(result, dropped):
    result.meta_filtered_findings = dropped
    return result


# (case id, list of scan results)
CASES = [
    ("tool_clean", [tool([])]),
    ("prompt_clean", [prompt([])]),
    ("resource_clean", [resource([])]),
    ("instructions_clean", [instructions([])]),
    ("unknown_type_skipped", [_Unknown()]),
    ("unknown_mixed_with_tool", [_Unknown(), tool([])]),
    ("single_high_finding", [tool([finding()])]),
    (
        "multiple_analyzers",
        [
            tool(
                [
                    finding(analyzer="YARA", severity="HIGH"),
                    finding(analyzer="API", severity="LOW", summary="minor"),
                    finding(analyzer="LLM", severity="MEDIUM", summary="mid"),
                ]
            )
        ],
    ),
    (
        "duplicate_threat_types_deduped",
        [
            tool(
                [
                    finding(threat_type="exfil", summary="s1"),
                    finding(threat_type="exfil", summary="s1"),
                    finding(threat_type="other", summary="s2"),
                ]
            )
        ],
    ),
    (
        "unknown_severity_forces_unknown_threat_name",
        [tool([finding(severity="UNKNOWN", threat_type=None)])],
    ),
    (
        "unknown_severity_with_unknown_threat_type",
        [tool([finding(severity="UNKNOWN", threat_type="unknown")])],
    ),
    (
        "finding_without_threat_type",
        [tool([finding(threat_type=None, summary="no type")])],
    ),
    ("with_taxonomy", [tool([finding(taxonomy=TAXONOMY)])]),
    (
        "taxonomy_on_later_finding_only",
        [tool([finding(summary="a"), finding(summary="b", taxonomy=TAXONOMY)])],
    ),
    (
        "with_threat_vuln_classification",
        [tool([finding(classification="VULNERABILITY")])],
    ),
    (
        "severity_precedence_low_then_high",
        [
            tool(
                [
                    finding(severity="LOW", summary="low one"),
                    finding(severity="HIGH", summary="high one"),
                ]
            )
        ],
    ),
    ("meta_dropped_all", [_with_meta(tool([]), [finding(summary="dropped")])]),
    (
        "meta_dropped_some",
        [_with_meta(tool([finding(summary="kept")]), [finding(summary="dropped")])],
    ),
    (
        "several_results",
        [tool([finding()]), prompt([]), resource([finding(severity="LOW")])],
    ),
    ("empty_input", []),
]
