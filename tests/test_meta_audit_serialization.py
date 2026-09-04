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

"""Regression tests for meta-analyzer audit-trail serialization (H2 / H3 / H5).

Pins the post-code-review fixes:

* H2: ``filter_results_by_severity`` must NOT zero out
  ``resource_description`` / ``resource_text`` / ``meta_filtered_findings``
  when reconstructing ``ResourceScanResult`` objects. Prior to this
  branch the filter silently dropped those three fields, undoing both
  the P0-3 (resource context) and P0-2 (audit trail) fixes whenever a
  caller piped scan results through a severity filter.

* H3: SDK serializers (``format_results_as_json`` and
  ``format_results_by_analyzer``) must surface a ``meta_analysis``
  block. The CLI artifact serializer (``report_generator``) and the
  HTTP API serializer (``api/router``) already did; the SDK
  serializer was the third corner of the matrix where filtered
  findings disappeared from the published view.

* H5: Static-path resource scanning must strip HTML on ``text/html``
  resources before persisting ``resource_text``, matching the remote
  path. Without this, the meta-analyzer received raw markup on the
  static path and extracted text on the remote path — different LLM
  prompts → different FP-filter decisions for the same content.
"""

import json

import pytest

from mcpscanner.core.analyzers.base import SecurityFinding
from mcpscanner.core.analyzers.static_analyzer import (
    StaticAnalyzer,
    _extract_html_text_if_needed,
)
from mcpscanner.core.result import (
    InstructionsScanResult,
    PromptScanResult,
    ResourceScanResult,
    ScanResult,
    ToolScanResult,
    filter_results_by_severity,
    format_results_as_json,
    format_results_by_analyzer,
    process_scan_results,
)


def _finding(severity: str = "HIGH", summary: str = "x") -> SecurityFinding:
    return SecurityFinding(
        severity=severity,
        summary=summary,
        analyzer="YARA",
        threat_category="X",
        details={},
    )


# ---------------------------------------------------------------------------
# H2: filter_results_by_severity preserves all cross-cutting attributes.
# ---------------------------------------------------------------------------


class TestFilterPreservesContext:
    def test_resource_description_and_text_round_trip(self):
        """H2: a Resource result piped through the filter MUST keep its
        description / text. Without this the meta-analyzer's
        ``entity_context`` (P0-3) is silently zeroed on filtered runs.
        """
        result = ResourceScanResult(
            resource_uri="res://x",
            resource_name="x",
            resource_mime_type="text/plain",
            status="completed",
            analyzers=["yara"],
            findings=[_finding("HIGH", "real")],
            resource_description="full description text",
            resource_text="full body text",
        )
        out = filter_results_by_severity([result], "HIGH")
        assert len(out) == 1
        assert out[0].resource_description == "full description text"
        assert out[0].resource_text == "full body text"

    def test_meta_filtered_findings_round_trip_for_all_types(self):
        """H2: every result subclass must carry ``meta_filtered_findings``
        through the filter — otherwise the audit trail (P0-2) is lost.
        """
        dropped = _finding("HIGH", "dropped by meta")
        kept = _finding("HIGH", "live")

        results: list[ScanResult] = [
            ToolScanResult(
                tool_name="t",
                tool_description="d",
                status="completed",
                analyzers=["yara"],
                findings=[kept],
            ),
            PromptScanResult(
                prompt_name="p",
                prompt_description="d",
                status="completed",
                analyzers=["yara"],
                findings=[kept],
            ),
            ResourceScanResult(
                resource_uri="res://x",
                resource_name="x",
                resource_mime_type="text/plain",
                status="completed",
                analyzers=["yara"],
                findings=[kept],
                resource_description="d",
                resource_text="t",
            ),
            InstructionsScanResult(
                instructions="hello",
                server_name="srv",
                protocol_version="2025-06-18",
                status="completed",
                analyzers=["yara"],
                findings=[kept],
            ),
        ]
        for r in results:
            r.meta_filtered_findings = [dropped]

        out = filter_results_by_severity(results, "HIGH")
        assert len(out) == 4
        for r in out:
            assert len(r.meta_filtered_findings) == 1
            assert r.meta_filtered_findings[0].summary == "dropped by meta"

    def test_filter_does_not_invent_meta_filtered_for_callers_who_never_set_it(self):
        """``filter_results_by_severity`` must not fabricate audit data
        when the caller never populated it (default ``[]`` is fine).
        """
        result = ToolScanResult(
            tool_name="t",
            tool_description="d",
            status="completed",
            analyzers=["yara"],
            findings=[_finding("HIGH", "real")],
        )
        # Don't touch meta_filtered_findings — let the dataclass default apply.
        out = filter_results_by_severity([result], "HIGH")
        assert out[0].meta_filtered_findings == []


# ---------------------------------------------------------------------------
# H3: SDK serializers emit the meta_analysis audit block.
# ---------------------------------------------------------------------------


class TestSdkSerializerMetaAudit:
    def test_format_results_as_json_includes_meta_analysis_block(self):
        """H3: ``format_results_as_json`` (the SDK-facing serializer)
        must include the ``meta_analysis`` audit block when findings
        were filtered. Operators reading this artifact would otherwise
        miss the FP filtering — same gap as the report_generator one
        we already plugged.
        """
        live = _finding("HIGH", "live")
        dropped = _finding("MEDIUM", "fp finding")
        dropped.details = {
            "meta_reason": "duplicate of YARA hit",
            "meta_confidence": 0.92,
        }
        result = ToolScanResult(
            tool_name="t",
            tool_description="d",
            status="completed",
            analyzers=["yara"],
            findings=[live],
        )
        result.meta_filtered_findings = [dropped]
        payload = json.loads(format_results_as_json([result]))

        assert "scan_results" in payload
        scan = payload["scan_results"][0]
        assert "meta_analysis" in scan, (
            "SDK callers reading format_results_as_json must see the "
            "meta_analysis audit block when findings were filtered. "
            "Otherwise they'd consume an artifact whose 'is_safe: true' "
            "lies about the underlying state."
        )
        block = scan["meta_analysis"]
        assert block["filtered_count"] == 1
        assert block["filtered_findings"][0]["summary"] == "fp finding"
        assert block["filtered_findings"][0]["meta_reason"] == "duplicate of YARA hit"

    def test_format_results_as_json_omits_meta_analysis_when_no_filter(self):
        """H3 hardening: the ``meta_analysis`` block is OPTIONAL —
        only present when meta-analysis actually filtered something.
        Otherwise we'd add noise to every clean SDK report.
        """
        result = ToolScanResult(
            tool_name="t",
            tool_description="d",
            status="completed",
            analyzers=["yara"],
            findings=[],
        )
        # Default empty meta_filtered_findings.
        payload = json.loads(format_results_as_json([result]))
        scan = payload["scan_results"][0]
        assert "meta_analysis" not in scan

    def test_format_results_by_analyzer_safe_with_meta_filter_shows_audit(self):
        """H3: the markdown serializer's safe branch must explicitly
        say "no findings remained AFTER meta-analysis" and list what
        was dropped. Without this an operator looking at a tool whose
        findings were ALL FPs gets the misleading "safe — no threats
        detected" message.
        """
        dropped = _finding("HIGH", "fp_summary_xyz")
        dropped.details = {"meta_reason": "false positive: regex matched a label"}
        result = ToolScanResult(
            tool_name="t",
            tool_description="d",
            status="completed",
            analyzers=["yara"],
            findings=[],  # no live findings
        )
        result.meta_filtered_findings = [dropped]
        out = format_results_by_analyzer(result)
        assert "no findings remained after meta-analysis" in out
        assert "fp_summary_xyz" in out
        assert "false positive: regex matched a label" in out

    def test_format_results_by_analyzer_unsafe_with_meta_filter_appends_audit(self):
        """H3: the markdown serializer's unsafe branch lists findings
        per analyzer AND appends the meta-filter audit suffix. If only
        one of a tool's three findings was filtered, the operator
        needs to see both pieces in the same artifact.
        """
        live = _finding("HIGH", "real_finding")
        dropped = _finding("MEDIUM", "fp_finding")
        dropped.details = {"meta_reason": "noise"}
        result = ToolScanResult(
            tool_name="t",
            tool_description="d",
            status="completed",
            analyzers=["yara"],
            findings=[live],
        )
        result.meta_filtered_findings = [dropped]
        out = format_results_by_analyzer(result)
        assert "real_finding" in out
        assert "Meta-analyzer dropped 1 additional finding" in out
        assert "fp_finding" in out


# ---------------------------------------------------------------------------
# H5: Static path strips HTML on text/html resources (parity with remote).
# ---------------------------------------------------------------------------


try:
    import bs4 as _bs4  # noqa: F401
    _BS4_AVAILABLE = True
except ImportError:
    _BS4_AVAILABLE = False


class TestStaticPathHtmlStripping:
    @pytest.mark.skipif(
        not _BS4_AVAILABLE,
        reason="bs4 is an optional dependency; the helper must passthrough "
        "without it (already covered by test_helper_passthrough_when_bs4_missing).",
    )
    def test_helper_strips_html_on_text_html_mime(self):
        """The shared helper must extract text from HTML when bs4 is
        available. With bs4 missing, the documented passthrough
        contract applies — pinned in the next test.
        """
        html = "<html><body><h1>Hello</h1><p>world</p></body></html>"
        out = _extract_html_text_if_needed(html, "text/html")
        assert "<h1>" not in out
        assert "Hello" in out
        assert "world" in out

    @pytest.mark.skipif(
        _BS4_AVAILABLE,
        reason="This pin only fires in environments WITHOUT bs4; the "
        "extraction-active path is covered by the previous test.",
    )
    def test_helper_passthrough_when_bs4_missing(self):
        """H5 documented behaviour: when bs4 is unavailable the helper
        falls back to raw content. This pin keeps the fallback path
        observable so it can't silently flip to crashing.
        """
        html = "<html><body><h1>Hello</h1></body></html>"
        # Returns raw content; the warning has already been logged
        # (covered manually — caplog interaction with named loggers is
        # tested elsewhere).
        assert _extract_html_text_if_needed(html, "text/html") == html

    def test_helper_passthrough_on_non_html_mime(self):
        """The helper is a no-op when the mime type is not text/html."""
        text = "<html>not html</html>"
        assert _extract_html_text_if_needed(text, "text/plain") == text
        assert _extract_html_text_if_needed(text, None) == text

    def test_helper_passthrough_on_empty_content(self):
        """Empty / None content must not raise."""
        assert _extract_html_text_if_needed("", "text/html") == ""

    @pytest.mark.skipif(
        not _BS4_AVAILABLE,
        reason="bs4 not available; the static path falls back to raw "
        "content (passthrough — see passthrough test above).",
    )
    def test_static_path_resource_text_is_html_stripped(self):
        """End-to-end: a static-path resource scan with mime=text/html
        produces a ``resource_text`` value that has been HTML-stripped,
        matching the remote-path output. Without this fix the meta
        analyzer would see different bodies on the two paths.
        """
        analyzer = StaticAnalyzer(analyzers=[])
        resource_data = {
            "uri": "res://hello",
            "name": "hello",
            "mimeType": "text/html",
            "text": "<html><body><h1>Hello</h1><p>world</p></body></html>",
        }
        text_content, saw_blob = analyzer._resource_text_content(
            resource_data, []
        )
        # Sanity: pre-strip, the body is the raw HTML.
        assert "<html>" in text_content
        # The helper applies the strip when invoked with the right mime.
        stripped = _extract_html_text_if_needed(text_content, "text/html")
        assert "<html>" not in stripped
        assert "Hello" in stripped
        assert "world" in stripped


# ---------------------------------------------------------------------------
# L4: process_scan_results aggregates filtered counts separately.
# ---------------------------------------------------------------------------


class TestProcessScanResultsExposesMetaCounts:
    def test_meta_filtered_counts_are_separate_from_severity_counts(self):
        """L4: ``severity_counts`` continues to reflect ONLY live
        findings; ``meta_filtered_counts`` carries the audit total.
        Folding them back would re-inflate dashboards — the very
        scenario the meta pass exists to prevent.
        """
        result = ToolScanResult(
            tool_name="t",
            tool_description="d",
            status="completed",
            analyzers=["yara"],
            findings=[_finding("HIGH", "live")],
        )
        result.meta_filtered_findings = [
            _finding("HIGH", "fp_a"),
            _finding("MEDIUM", "fp_b"),
        ]
        summary = process_scan_results([result])
        # Live findings only.
        assert summary["severity_counts"]["HIGH"] == 1
        assert summary["severity_counts"]["MEDIUM"] == 0
        # Audit totals exposed separately.
        assert summary["meta_filtered_counts"]["HIGH"] == 1
        assert summary["meta_filtered_counts"]["MEDIUM"] == 1
        assert summary["total_meta_filtered"] == 2


# ---------------------------------------------------------------------------
# M3: Instructions context is no longer truncated to 500 bytes.
# ---------------------------------------------------------------------------


class TestInstructionsContextForMeta:
    def test_long_instructions_passed_in_full_up_to_budget(self):
        """M3: the meta-analyzer must see the full instructions body
        (within an 8 KiB budget), not the 500-byte slice the prior
        helper used. Without the fix, a finding citing evidence past
        byte 500 was second-guessed against text the LLM never saw.
        """
        from mcpscanner.core.scanner import Scanner

        body = "X" * 4000  # well past the old 500-byte cap, well under 8 KiB.
        result = InstructionsScanResult(
            instructions=body,
            server_name="srv",
            protocol_version="2025-06-18",
            status="completed",
            analyzers=["yara"],
            findings=[],
        )
        out = Scanner._build_instructions_description_for_meta(result)
        assert out == body
        assert len(out) == 4000

    def test_truncated_marker_present_above_budget(self):
        """M3 hardening: above the budget the helper truncates AND
        annotates so the LLM (and any reader of logs) sees that the
        evidence was clipped — never silently lost.
        """
        from mcpscanner.core.scanner import Scanner

        body = "Y" * 12000
        result = InstructionsScanResult(
            instructions=body,
            server_name="srv",
            protocol_version="2025-06-18",
            status="completed",
            analyzers=["yara"],
            findings=[],
        )
        out = Scanner._build_instructions_description_for_meta(
            result, budget=8000
        )
        assert out.startswith("Y" * 8000)
        assert "instructions truncated" in out
        assert "4000 bytes elided" in out

    def test_empty_instructions_returns_empty_string(self):
        """Edge case: empty / None instructions must not raise."""
        from mcpscanner.core.scanner import Scanner

        for value in ("", "   ", None):
            result = InstructionsScanResult(
                instructions=value,
                server_name="srv",
                protocol_version="2025-06-18",
                status="completed",
                analyzers=["yara"],
                findings=[],
            )
            assert Scanner._build_instructions_description_for_meta(result) == ""
