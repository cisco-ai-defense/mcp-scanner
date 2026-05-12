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

"""Tests for the LLM Meta-Analyzer module.

The meta-analyzer's responsibility is intentionally narrow: filter false
positives out of analyzer findings. It must NEVER add new findings, enrich
true positives, or prioritize/correlate them.
"""

import json

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from mcpscanner.config import Config
from mcpscanner.core.analyzers.base import SecurityFinding
from mcpscanner.core.analyzers.meta_analyzer import (
    MetaAnalysisResult,
    MetaAnalyzer,
    apply_meta_analysis,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(
    severity="HIGH",
    summary="Test finding",
    analyzer="YARA",
    threat_category="SECURITY VIOLATION",
    details=None,
):
    return SecurityFinding(
        severity=severity,
        summary=summary,
        analyzer=analyzer,
        threat_category=threat_category,
        details=details or {},
    )


def _make_config(**overrides):
    defaults = {"llm_provider_api_key": "test-key"}
    defaults.update(overrides)
    return Config(**defaults)


def _mock_llm_response(json_body: dict) -> MagicMock:
    """Build a MagicMock mimicking litellm acompletion response."""
    mock_response = MagicMock()
    mock_response.choices = [MagicMock()]
    mock_response.choices[0].message.content = json.dumps(json_body)
    return mock_response


# ---------------------------------------------------------------------------
# MetaAnalysisResult
# ---------------------------------------------------------------------------

class TestMetaAnalysisResult:
    """Tests for the MetaAnalysisResult dataclass."""

    def test_defaults_are_empty(self):
        """All fields default to empty collections."""
        result = MetaAnalysisResult()
        assert result.validated_findings == []
        assert result.false_positives == []
        assert result.missed_threats == []
        assert result.priority_order == []
        assert result.correlations == []
        assert result.recommendations == []
        assert result.overall_risk_assessment == {}

    def test_to_dict_includes_summary(self):
        """to_dict produces a summary with counts."""
        result = MetaAnalysisResult(
            validated_findings=[{"_index": 0}],
            false_positives=[{"_index": 1}],
            missed_threats=[{"severity": "HIGH"}],
            recommendations=[{"action": "fix it"}],
        )
        d = result.to_dict()
        assert d["summary"]["total_original"] == 2
        assert d["summary"]["validated_count"] == 1
        assert d["summary"]["false_positive_count"] == 1
        assert d["summary"]["missed_threats_count"] == 1
        assert d["summary"]["recommendations_count"] == 1


# ---------------------------------------------------------------------------
# MetaAnalyzer — Initialization
# ---------------------------------------------------------------------------

class TestMetaAnalyzerInit:
    """Tests for MetaAnalyzer construction."""

    def test_init_with_valid_config(self):
        """MetaAnalyzer initializes with a valid API key."""
        config = _make_config()
        analyzer = MetaAnalyzer(config)
        assert analyzer.name == "META"
        assert analyzer._model == config.llm_model
        assert analyzer._temperature == 0.1
        assert analyzer._max_tokens == 8192

    def test_init_without_api_key_raises(self):
        """MetaAnalyzer raises ValueError without an API key."""
        config = Config()
        with pytest.raises(ValueError, match="Meta-Analyzer LLM API key not configured"):
            MetaAnalyzer(config)

    def test_init_loads_system_prompt(self):
        """MetaAnalyzer loads the system prompt from file."""
        config = _make_config()
        analyzer = MetaAnalyzer(config)
        assert len(analyzer._system_prompt) > 100
        assert (
            "false positive" in analyzer._system_prompt.lower()
            or "security analyst" in analyzer._system_prompt.lower()
        )

    @patch(
        "mcpscanner.core.analyzers.meta_analyzer.MCPScannerConstants.get_prompts_path"
    )
    def test_init_falls_back_on_missing_prompt(self, mock_path):
        """MetaAnalyzer uses fallback prompt when file is missing."""
        mock_path.return_value = MagicMock()
        mock_path.return_value.__truediv__ = MagicMock(
            side_effect=FileNotFoundError("not found")
        )
        config = _make_config()
        analyzer = MetaAnalyzer(config)
        assert "senior security analyst" in analyzer._system_prompt.lower()


# ---------------------------------------------------------------------------
# MetaAnalyzer — Serialization & Prompt Building
# ---------------------------------------------------------------------------

class TestMetaAnalyzerPrompts:
    """Tests for finding serialization and prompt construction."""

    def test_serialize_findings_includes_index_and_analyzer(self):
        """Each finding gets an _index and its analyzer name preserved."""
        config = _make_config()
        analyzer = MetaAnalyzer(config)

        findings = [
            _make_finding(analyzer="YARA", summary="YARA threat"),
            _make_finding(analyzer="LLM", summary="LLM threat"),
        ]
        serialized = json.loads(analyzer._serialize_findings(findings))

        assert len(serialized) == 2
        assert serialized[0]["_index"] == 0
        assert serialized[0]["analyzer"] == "YARA"
        assert serialized[0]["summary"] == "YARA threat"
        assert serialized[1]["_index"] == 1
        assert serialized[1]["analyzer"] == "LLM"

    def test_serialize_findings_includes_details(self):
        """Details like threat_type and evidence are carried through."""
        config = _make_config()
        analyzer = MetaAnalyzer(config)

        findings = [
            _make_finding(details={"threat_type": "DATA EXFILTRATION", "evidence": "reads ~/.ssh"}),
        ]
        serialized = json.loads(analyzer._serialize_findings(findings))
        assert serialized[0]["threat_type"] == "DATA EXFILTRATION"
        assert "ssh" in serialized[0]["evidence"]

    def test_serialize_findings_truncates_long_evidence(self):
        """Evidence longer than 300 chars is truncated."""
        config = _make_config()
        analyzer = MetaAnalyzer(config)

        long_evidence = "x" * 500
        findings = [_make_finding(details={"evidence": long_evidence})]
        serialized = json.loads(analyzer._serialize_findings(findings))
        assert len(serialized[0]["evidence"]) == 300

    def test_build_user_prompt_contains_entity_context(self):
        """User prompt includes entity name, type, description."""
        config = _make_config()
        analyzer = MetaAnalyzer(config)

        findings_data = json.dumps([{"_index": 0, "analyzer": "YARA"}])
        prompt = analyzer._build_user_prompt(
            entity_context={"type": "tool", "name": "my_tool", "description": "does stuff"},
            findings_data=findings_data,
            analyzers_used=["YARA", "LLM"],
            start_tag="<START>",
            end_tag="<END>",
        )
        assert "my_tool" in prompt
        assert "does stuff" in prompt
        assert "YARA" in prompt
        assert "LLM" in prompt
        assert "1 findings" in prompt

    def test_build_user_prompt_restricts_to_false_positive_filtering(self):
        """User prompt explicitly disallows enrichment / new threats."""
        config = _make_config()
        analyzer = MetaAnalyzer(config)
        prompt = analyzer._build_user_prompt(
            entity_context={"type": "tool", "name": "x", "description": "y"},
            findings_data=json.dumps([{"_index": 0}]),
            analyzers_used=["YARA"],
            start_tag="<S>",
            end_tag="<E>",
        )
        lowered = prompt.lower()
        assert "false positive" in lowered
        # Output schema must only ask for false_positives.
        assert "false_positives" in prompt
        assert "missed_threats" not in prompt
        assert "validated_findings" not in prompt
        assert "priority_order" not in prompt

    def test_build_user_prompt_includes_parameters(self):
        """User prompt includes parameters schema when provided."""
        config = _make_config()
        analyzer = MetaAnalyzer(config)

        prompt = analyzer._build_user_prompt(
            entity_context={
                "type": "tool",
                "name": "cmd",
                "description": "run commands",
                "parameters": {"command": {"type": "string"}},
            },
            findings_data=json.dumps([{"_index": 0}]),
            analyzers_used=["LLM"],
            start_tag="<S>",
            end_tag="<E>",
        )
        assert "Parameters Schema" in prompt
        assert '"command"' in prompt


# ---------------------------------------------------------------------------
# MetaAnalyzer — JSON Extraction
# ---------------------------------------------------------------------------

class TestExtractJsonFromResponse:
    """Tests for _extract_json_from_response strategies."""

    def setup_method(self):
        self.analyzer = MetaAnalyzer(_make_config())

    def test_pure_json(self):
        """Parses a pure JSON string."""
        data = {"false_positives": [{"_index": 0, "false_positive_reason": "benign"}]}
        result = self.analyzer._extract_json_from_response(json.dumps(data))
        assert result["false_positives"][0]["_index"] == 0

    def test_json_in_markdown_fence(self):
        """Extracts JSON from a ```json code block."""
        raw = 'Here is my analysis:\n```json\n{"false_positives": []}\n```\nDone.'
        result = self.analyzer._extract_json_from_response(raw)
        assert result["false_positives"] == []

    def test_json_embedded_in_text(self):
        """Extracts JSON embedded in surrounding prose."""
        raw = 'Analysis follows: {"key": "value"} end of analysis.'
        result = self.analyzer._extract_json_from_response(raw)
        assert result["key"] == "value"

    def test_empty_response_raises(self):
        """Empty/whitespace-only response raises ValueError."""
        with pytest.raises(ValueError, match="Empty response"):
            self.analyzer._extract_json_from_response("")
        with pytest.raises(ValueError, match="Empty response"):
            self.analyzer._extract_json_from_response("   ")

    def test_no_json_raises(self):
        """Pure prose with no JSON raises ValueError."""
        with pytest.raises(ValueError, match="No valid JSON"):
            self.analyzer._extract_json_from_response("This is just text with no braces.")


# ---------------------------------------------------------------------------
# MetaAnalyzer — Response Parsing (false_positives only)
# ---------------------------------------------------------------------------

class TestParseResponse:
    """_parse_response only consumes the false_positives field."""

    def setup_method(self):
        self.analyzer = MetaAnalyzer(_make_config())
        self.findings = [_make_finding(), _make_finding(analyzer="LLM")]

    def test_parses_false_positives(self):
        """Only false_positives is consumed; other fields are dropped."""
        response = json.dumps({
            "false_positives": [{"_index": 1, "false_positive_reason": "benign"}],
            "validated_findings": [{"_index": 0, "confidence": "HIGH"}],
            "missed_threats": [{"severity": "HIGH"}],
            "priority_order": [0, 1],
            "correlations": [{"group": "x"}],
            "recommendations": [{"action": "y"}],
            "overall_risk_assessment": {"risk_level": "HIGH"},
        })
        result = self.analyzer._parse_response(response, self.findings)
        assert len(result.false_positives) == 1
        assert result.false_positives[0]["_index"] == 1
        # All ignored fields stay at defaults.
        assert result.validated_findings == []
        assert result.missed_threats == []
        assert result.priority_order == []
        assert result.correlations == []
        assert result.recommendations == []

    def test_invalid_json_keeps_all_findings(self):
        """Unparsable response yields no FP suggestions (keep everything)."""
        result = self.analyzer._parse_response("not json at all", self.findings)
        assert result.false_positives == []
        assert result.overall_risk_assessment["risk_level"] == "UNKNOWN"

    def test_partial_fields(self):
        """Missing false_positives field defaults to empty list."""
        response = json.dumps({"validated_findings": [{"_index": 0}]})
        result = self.analyzer._parse_response(response, self.findings)
        assert result.false_positives == []


# ---------------------------------------------------------------------------
# MetaAnalyzer — analyze_findings (async, mocked LLM)
# ---------------------------------------------------------------------------

class TestAnalyzeFindings:
    """Tests for the full analyze_findings pipeline."""

    @pytest.mark.asyncio
    @patch("mcpscanner.core.analyzers.meta_analyzer.acompletion")
    async def test_empty_findings_returns_safe(self, mock_completion):
        """No findings → immediate SAFE result without calling LLM."""
        analyzer = MetaAnalyzer(_make_config())
        result = await analyzer.analyze_findings(
            findings=[],
            analyzers_used=["YARA"],
            entity_context={"type": "tool", "name": "safe_tool"},
        )
        assert result.overall_risk_assessment["risk_level"] == "SAFE"
        mock_completion.assert_not_called()

    @pytest.mark.asyncio
    @patch("mcpscanner.core.analyzers.meta_analyzer.acompletion")
    async def test_no_followup_request_is_made(self, mock_completion):
        """The follow-up coverage pass has been removed; only one LLM call."""
        mock_completion.return_value = _mock_llm_response({
            "false_positives": [{"_index": 1, "false_positive_reason": "benign"}],
        })
        analyzer = MetaAnalyzer(_make_config())
        findings = [_make_finding(), _make_finding(analyzer="LLM")]
        result = await analyzer.analyze_findings(
            findings=findings,
            analyzers_used=["YARA", "LLM"],
            entity_context={"type": "tool", "name": "t"},
        )
        assert mock_completion.call_count == 1
        assert len(result.false_positives) == 1

    @pytest.mark.asyncio
    @patch("mcpscanner.core.analyzers.meta_analyzer.acompletion")
    async def test_llm_failure_keeps_all_findings(self, mock_completion):
        """LLM API failure returns an empty FP list so nothing is filtered."""
        mock_completion.side_effect = Exception("API timeout")
        analyzer = MetaAnalyzer(_make_config())
        findings = [_make_finding()]
        result = await analyzer.analyze_findings(
            findings=findings,
            analyzers_used=["YARA"],
            entity_context={"type": "tool", "name": "test"},
        )
        assert result.false_positives == []
        assert result.overall_risk_assessment["risk_level"] == "UNKNOWN"
        assert "failed" in result.overall_risk_assessment["summary"].lower()

    @pytest.mark.asyncio
    @patch("mcpscanner.core.analyzers.meta_analyzer.acompletion")
    async def test_with_false_positive_detection(self, mock_completion):
        """Meta-analysis identifies a finding as false positive."""
        mock_completion.return_value = _mock_llm_response({
            "false_positives": [
                {"_index": 1, "false_positive_reason": "Benign calculator operation"},
            ],
        })

        analyzer = MetaAnalyzer(_make_config())
        findings = [
            _make_finding(severity="HIGH", summary="Prompt injection"),
            _make_finding(severity="LOW", summary="Suspicious pattern in calculator"),
        ]
        result = await analyzer.analyze_findings(
            findings=findings,
            analyzers_used=["YARA"],
            entity_context={"type": "tool", "name": "calc"},
        )

        assert len(result.false_positives) == 1
        assert result.false_positives[0]["_index"] == 1
        assert "Benign" in result.false_positives[0]["false_positive_reason"]


# ---------------------------------------------------------------------------
# apply_meta_analysis — strict FP-only filtering
# ---------------------------------------------------------------------------

class TestApplyMetaAnalysis:
    """apply_meta_analysis only filters false positives — nothing else."""

    def test_false_positives_are_filtered_out(self):
        """FP-flagged findings are removed from the returned list."""
        findings = [
            _make_finding(summary="Real threat"),
            _make_finding(summary="Benign pattern"),
        ]
        meta_result = MetaAnalysisResult(
            false_positives=[
                {"_index": 1, "reason": "Not a real threat", "confidence": "HIGH"}
            ],
        )
        kept = apply_meta_analysis(findings, meta_result)

        assert len(kept) == 1
        assert kept[0].summary == "Real threat"

    def test_dropped_finding_records_audit_trail(self):
        """The original finding object records why it was dropped."""
        keep = _make_finding(summary="Real threat")
        drop = _make_finding(summary="Benign pattern")
        meta_result = MetaAnalysisResult(
            false_positives=[
                {"_index": 1, "reason": "Standard parameter name", "confidence": "HIGH"}
            ],
        )
        kept = apply_meta_analysis([keep, drop], meta_result)

        assert kept == [keep]
        assert drop.details["meta_false_positive"] is True
        assert drop.details["meta_reason"] == "Standard parameter name"
        assert drop.details["meta_confidence"] == "HIGH"

    def test_true_positives_are_not_enriched(self):
        """No enrichment fields are ever added to surviving findings."""
        finding = _make_finding(details={"existing": "value"})
        meta_result = MetaAnalysisResult(
            validated_findings=[
                {
                    "_index": 0,
                    "confidence": "HIGH",
                    "confidence_reason": "Clear prompt injection",
                    "exploitability": "EASY",
                    "impact": "HIGH",
                }
            ],
            priority_order=[0],
            correlations=[{"group": "x"}],
            recommendations=[{"action": "fix"}],
            overall_risk_assessment={"risk_level": "HIGH"},
        )
        kept = apply_meta_analysis([finding], meta_result)

        assert kept == [finding]
        details = kept[0].details
        # Nothing meta-related is added to a TP.
        for forbidden in (
            "meta_validated",
            "meta_confidence",
            "meta_confidence_reason",
            "meta_exploitability",
            "meta_impact",
            "meta_priority",
            "meta_correlations",
            "meta_recommendations",
            "meta_risk_assessment",
            "meta_reviewed",
            "meta_false_positive",
            "meta_reason",
        ):
            assert forbidden not in details, f"{forbidden} should not be added to TPs"
        # Pre-existing details are preserved.
        assert details["existing"] == "value"

    def test_missed_threats_are_ignored(self):
        """Missed threats from the LLM never become new findings."""
        findings = [_make_finding()]
        meta_result = MetaAnalysisResult(
            missed_threats=[
                {
                    "severity": "HIGH",
                    "threat_category": "DATA EXFILTRATION",
                    "title": "SSH key theft",
                    "description": "Tool reads private keys",
                }
            ],
        )
        kept = apply_meta_analysis(findings, meta_result)
        # Only the original finding remains; no synthesized finding is added.
        assert len(kept) == 1
        assert kept[0] is findings[0]

    def test_no_correlations_or_recommendations_are_attached(self):
        """Correlations / recommendations / risk assessment are never written."""
        findings = [_make_finding(), _make_finding()]
        meta_result = MetaAnalysisResult(
            correlations=[{"group": "x"}],
            recommendations=[{"action": "y"}],
            overall_risk_assessment={"risk_level": "HIGH"},
        )
        kept = apply_meta_analysis(findings, meta_result)
        for f in kept:
            assert "meta_correlations" not in f.details
            assert "meta_recommendations" not in f.details
            assert "meta_risk_assessment" not in f.details

    def test_empty_findings_and_empty_meta(self):
        """Empty findings + empty meta result → empty output."""
        kept = apply_meta_analysis([], MetaAnalysisResult())
        assert kept == []

    def test_finding_with_none_details_is_unmodified_when_kept(self):
        """A surviving finding gets no meta-related fields added to details."""
        finding = SecurityFinding(
            severity="LOW",
            summary="test",
            analyzer="API",
            threat_category="UNKNOWN",
            details=None,
        )
        kept = apply_meta_analysis([finding], MetaAnalysisResult())
        assert kept == [finding]
        # Whatever default the SecurityFinding chose for details, no meta_*
        # keys should have been written by apply_meta_analysis.
        details = finding.details or {}
        assert not any(k.startswith("meta_") for k in details)

    def test_finding_with_none_details_is_initialized_when_dropped(self):
        """A dropped finding's details dict is created so the audit trail fits."""
        finding = SecurityFinding(
            severity="LOW",
            summary="test",
            analyzer="API",
            threat_category="UNKNOWN",
            details=None,
        )
        meta_result = MetaAnalysisResult(
            false_positives=[{"_index": 0, "false_positive_reason": "benign"}],
        )
        kept = apply_meta_analysis([finding], meta_result)
        assert kept == []
        assert finding.details is not None
        assert finding.details["meta_false_positive"] is True

    def test_multiple_analyzers_only_fp_filtered(self):
        """Findings from different analyzers are filtered or kept as-is."""
        findings = [
            _make_finding(analyzer="YARA", summary="YARA finding"),
            _make_finding(analyzer="LLM", summary="LLM finding"),
            _make_finding(analyzer="API", summary="API finding"),
        ]
        meta_result = MetaAnalysisResult(
            false_positives=[
                {"_index": 2, "reason": "API false alarm"},
            ],
        )
        kept = apply_meta_analysis(findings, meta_result)

        assert len(kept) == 2
        assert kept[0].analyzer == "YARA"
        assert kept[1].analyzer == "LLM"
        # Surviving findings are not annotated.
        for f in kept:
            assert "meta_false_positive" not in f.details
            assert "meta_validated" not in f.details
