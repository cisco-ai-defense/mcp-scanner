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

"""Tests for the LLM Meta-Analyzer module."""

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

    def test_to_dict_roundtrip_fields(self):
        """All fields appear in the dict representation."""
        result = MetaAnalysisResult(
            validated_findings=[{"_index": 0, "confidence": "HIGH"}],
            priority_order=[0],
            correlations=[{"group": "A", "indices": [0]}],
            overall_risk_assessment={"risk_level": "HIGH", "summary": "Dangerous"},
        )
        d = result.to_dict()
        assert d["validated_findings"] == result.validated_findings
        assert d["priority_order"] == [0]
        assert d["correlations"][0]["group"] == "A"
        assert d["overall_risk_assessment"]["risk_level"] == "HIGH"


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
        assert "security" in analyzer._system_prompt.lower() or "analyst" in analyzer._system_prompt.lower()

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
        data = {"validated_findings": [{"_index": 0}]}
        result = self.analyzer._extract_json_from_response(json.dumps(data))
        assert result["validated_findings"][0]["_index"] == 0

    def test_json_in_markdown_fence(self):
        """Extracts JSON from a ```json code block."""
        raw = 'Here is my analysis:\n```json\n{"risk": "HIGH"}\n```\nDone.'
        result = self.analyzer._extract_json_from_response(raw)
        assert result["risk"] == "HIGH"

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
# MetaAnalyzer — Response Parsing
# ---------------------------------------------------------------------------

class TestParseResponse:
    """Tests for _parse_response."""

    def setup_method(self):
        self.analyzer = MetaAnalyzer(_make_config())
        self.findings = [_make_finding(), _make_finding(analyzer="LLM")]

    def test_valid_response(self):
        """Parses a well-formed meta-analysis JSON response."""
        response = json.dumps({
            "validated_findings": [
                {"_index": 0, "confidence": "HIGH"},
                {"_index": 1, "confidence": "MEDIUM"},
            ],
            "false_positives": [],
            "missed_threats": [],
            "priority_order": [0, 1],
            "correlations": [],
            "recommendations": [{"action": "review tool"}],
            "overall_risk_assessment": {"risk_level": "HIGH", "summary": "Dangerous tool"},
        })
        result = self.analyzer._parse_response(response, self.findings)

        assert len(result.validated_findings) == 2
        assert result.validated_findings[0]["confidence"] == "HIGH"
        assert result.priority_order == [0, 1]
        assert result.overall_risk_assessment["risk_level"] == "HIGH"

    def test_invalid_json_returns_fallback(self):
        """Unparsable response returns fallback preserving all findings."""
        result = self.analyzer._parse_response("not json at all", self.findings)

        assert len(result.validated_findings) == 2
        assert result.validated_findings[0]["_index"] == 0
        assert result.validated_findings[1]["_index"] == 1
        assert result.overall_risk_assessment["risk_level"] == "UNKNOWN"

    def test_partial_fields(self):
        """Missing fields default to empty lists/dicts."""
        response = json.dumps({"validated_findings": [{"_index": 0}]})
        result = self.analyzer._parse_response(response, self.findings)

        assert len(result.validated_findings) == 1
        assert result.false_positives == []
        assert result.missed_threats == []
        assert result.priority_order == []


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
    async def test_successful_analysis(self, mock_completion):
        """Findings from two analyzers are analyzed and enriched."""
        mock_completion.return_value = _mock_llm_response({
            "validated_findings": [
                {"_index": 0, "confidence": "HIGH", "exploitability": "EASY", "impact": "HIGH"},
                {"_index": 1, "confidence": "MEDIUM", "exploitability": "MODERATE", "impact": "MEDIUM"},
            ],
            "false_positives": [],
            "missed_threats": [],
            "priority_order": [0, 1],
            "correlations": [{"group": "exfil", "finding_indices": [0, 1]}],
            "recommendations": [{"action": "Remove SSH key reading"}],
            "overall_risk_assessment": {"risk_level": "HIGH", "summary": "Data exfiltration risk"},
        })

        analyzer = MetaAnalyzer(_make_config())
        findings = [
            _make_finding(analyzer="YARA", summary="SSH key access"),
            _make_finding(analyzer="LLM", summary="Data exfiltration"),
        ]
        result = await analyzer.analyze_findings(
            findings=findings,
            analyzers_used=["YARA", "LLM"],
            entity_context={"type": "tool", "name": "cmd_exec", "description": "Execute commands"},
        )

        assert len(result.validated_findings) == 2
        assert result.validated_findings[0]["confidence"] == "HIGH"
        assert result.priority_order == [0, 1]
        assert result.overall_risk_assessment["risk_level"] == "HIGH"
        assert len(result.correlations) == 1

        mock_completion.assert_called_once()
        call_args = mock_completion.call_args
        assert call_args[1]["model"] == analyzer._model
        messages = call_args[1]["messages"]
        assert len(messages) == 2
        assert "YARA" in messages[1]["content"]
        assert "LLM" in messages[1]["content"]

    @pytest.mark.asyncio
    @patch("mcpscanner.core.analyzers.meta_analyzer.acompletion")
    async def test_llm_failure_preserves_findings(self, mock_completion):
        """LLM API failure returns graceful fallback preserving all findings."""
        mock_completion.side_effect = Exception("API timeout")

        analyzer = MetaAnalyzer(_make_config())
        findings = [_make_finding()]
        result = await analyzer.analyze_findings(
            findings=findings,
            analyzers_used=["YARA"],
            entity_context={"type": "tool", "name": "test"},
        )

        assert len(result.validated_findings) == 1
        assert result.validated_findings[0]["_index"] == 0
        assert result.overall_risk_assessment["risk_level"] == "UNKNOWN"
        assert "failed" in result.overall_risk_assessment["summary"].lower()

    @pytest.mark.asyncio
    @patch("mcpscanner.core.analyzers.meta_analyzer.acompletion")
    async def test_with_false_positive_detection(self, mock_completion):
        """Meta-analysis identifies a finding as false positive."""
        mock_completion.return_value = _mock_llm_response({
            "validated_findings": [
                {"_index": 0, "confidence": "HIGH"},
            ],
            "false_positives": [
                {"_index": 1, "reason": "Benign calculator operation", "confidence": "HIGH"},
            ],
            "missed_threats": [],
            "priority_order": [0],
            "correlations": [],
            "recommendations": [],
            "overall_risk_assessment": {"risk_level": "MEDIUM"},
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
        assert "Benign" in result.false_positives[0]["reason"]

    @pytest.mark.asyncio
    @patch("mcpscanner.core.analyzers.meta_analyzer.acompletion")
    async def test_missed_threat_detection(self, mock_completion):
        """Meta-analysis detects a threat that primary analyzers missed."""
        mock_completion.return_value = _mock_llm_response({
            "validated_findings": [{"_index": 0, "confidence": "HIGH"}],
            "false_positives": [],
            "missed_threats": [
                {
                    "severity": "HIGH",
                    "threat_category": "CREDENTIAL HARVESTING",
                    "title": "Hidden credential theft",
                    "description": "Tool silently reads SSH keys",
                    "detection_reason": "Analyzers missed indirect file access pattern",
                    "confidence": "MEDIUM",
                    "remediation": "Block access to ~/.ssh directory",
                },
            ],
            "priority_order": [0],
            "correlations": [],
            "recommendations": [],
            "overall_risk_assessment": {"risk_level": "HIGH"},
        })

        analyzer = MetaAnalyzer(_make_config())
        findings = [_make_finding()]
        result = await analyzer.analyze_findings(
            findings=findings,
            analyzers_used=["YARA"],
            entity_context={"type": "tool", "name": "file_tool"},
        )

        assert len(result.missed_threats) == 1
        assert result.missed_threats[0]["severity"] == "HIGH"
        assert result.missed_threats[0]["threat_category"] == "CREDENTIAL HARVESTING"


# ---------------------------------------------------------------------------
# apply_meta_analysis
# ---------------------------------------------------------------------------

class TestApplyMetaAnalysis:
    """Tests for the apply_meta_analysis function."""

    def test_false_positive_marking(self):
        """Findings flagged as FP get meta_false_positive=True in details."""
        findings = [
            _make_finding(summary="Real threat"),
            _make_finding(summary="Benign pattern"),
        ]
        meta_result = MetaAnalysisResult(
            validated_findings=[{"_index": 0, "confidence": "HIGH"}],
            false_positives=[{"_index": 1, "reason": "Not a real threat", "confidence": "HIGH"}],
        )
        enriched = apply_meta_analysis(findings, meta_result)

        assert len(enriched) == 2
        assert enriched[0].details["meta_false_positive"] is False
        assert enriched[1].details["meta_false_positive"] is True
        assert enriched[1].details["meta_reason"] == "Not a real threat"
        assert enriched[1].details["meta_confidence"] == "HIGH"

    def test_validated_finding_enrichment(self):
        """Validated findings get meta_validated and related metadata."""
        findings = [_make_finding()]
        meta_result = MetaAnalysisResult(
            validated_findings=[{
                "_index": 0,
                "confidence": "HIGH",
                "confidence_reason": "Clear prompt injection",
                "exploitability": "EASY",
                "impact": "HIGH",
            }],
        )
        enriched = apply_meta_analysis(findings, meta_result)

        assert enriched[0].details["meta_validated"] is True
        assert enriched[0].details["meta_confidence"] == "HIGH"
        assert enriched[0].details["meta_confidence_reason"] == "Clear prompt injection"
        assert enriched[0].details["meta_exploitability"] == "EASY"
        assert enriched[0].details["meta_impact"] == "HIGH"
        assert enriched[0].details["meta_false_positive"] is False

    def test_priority_assignment(self):
        """Priority from meta-analysis is assigned to finding details."""
        findings = [
            _make_finding(summary="Low priority"),
            _make_finding(summary="High priority"),
        ]
        meta_result = MetaAnalysisResult(
            validated_findings=[
                {"_index": 0, "confidence": "LOW"},
                {"_index": 1, "confidence": "HIGH"},
            ],
            priority_order=[1, 0],
        )
        enriched = apply_meta_analysis(findings, meta_result)

        assert enriched[0].details["meta_priority"] == 2
        assert enriched[1].details["meta_priority"] == 1

    def test_missed_threats_attributed_to_llm(self):
        """Missed threats are added as new findings with analyzer='LLM'."""
        findings = [_make_finding()]
        meta_result = MetaAnalysisResult(
            validated_findings=[{"_index": 0}],
            missed_threats=[{
                "severity": "HIGH",
                "threat_category": "DATA EXFILTRATION",
                "title": "SSH key theft",
                "description": "Tool reads private keys",
                "detection_reason": "Pattern missed by YARA",
                "confidence": "MEDIUM",
                "remediation": "Block ~/.ssh access",
            }],
        )
        enriched = apply_meta_analysis(findings, meta_result)

        assert len(enriched) == 2
        new_finding = enriched[1]
        assert new_finding.analyzer == "LLM"
        assert new_finding.severity == "HIGH"
        assert new_finding.threat_category == "DATA EXFILTRATION"
        assert "SSH key theft" in new_finding.summary
        assert new_finding.details["meta_detected"] is True
        assert new_finding.details["meta_false_positive"] is False
        assert new_finding.details["remediation"] == "Block ~/.ssh access"

    def test_missed_threat_invalid_severity_defaults_to_high(self):
        """Invalid severity on a missed threat defaults to HIGH."""
        findings = []
        meta_result = MetaAnalysisResult(
            missed_threats=[{"severity": "CRITICAL", "title": "Bad thing"}],
        )
        enriched = apply_meta_analysis(findings, meta_result)
        assert enriched[0].severity == "HIGH"

    def test_correlations_on_highest_priority_finding(self):
        """Correlations are attached to the finding with meta_priority==1."""
        findings = [
            _make_finding(summary="Secondary"),
            _make_finding(summary="Primary"),
        ]
        meta_result = MetaAnalysisResult(
            validated_findings=[
                {"_index": 0, "confidence": "LOW"},
                {"_index": 1, "confidence": "HIGH"},
            ],
            priority_order=[1, 0],
            correlations=[{"group": "exfil", "finding_indices": [0, 1]}],
            recommendations=[{"action": "fix this"}],
            overall_risk_assessment={"risk_level": "HIGH", "summary": "Dangerous"},
        )
        enriched = apply_meta_analysis(findings, meta_result)

        primary = enriched[1]
        assert primary.details["meta_priority"] == 1
        assert primary.details["meta_correlations"] == meta_result.correlations
        assert primary.details["meta_recommendations"] == meta_result.recommendations
        assert primary.details["meta_risk_assessment"]["risk_level"] == "HIGH"

        secondary = enriched[0]
        assert "meta_correlations" not in secondary.details

    def test_correlations_fallback_to_first_finding(self):
        """Without priority_order, correlations fall back to first finding."""
        findings = [_make_finding(), _make_finding()]
        meta_result = MetaAnalysisResult(
            validated_findings=[{"_index": 0}, {"_index": 1}],
            correlations=[{"group": "related"}],
        )
        enriched = apply_meta_analysis(findings, meta_result)
        assert "meta_correlations" in enriched[0].details
        assert "meta_correlations" not in enriched[1].details

    def test_empty_findings_and_empty_meta(self):
        """Empty findings + empty meta result → empty output."""
        enriched = apply_meta_analysis([], MetaAnalysisResult())
        assert enriched == []

    def test_finding_with_none_details_gets_initialized(self):
        """A finding whose details is None gets a dict before enrichment."""
        finding = SecurityFinding(
            severity="LOW",
            summary="test",
            analyzer="API",
            threat_category="UNKNOWN",
            details=None,
        )
        meta_result = MetaAnalysisResult(
            validated_findings=[{"_index": 0, "confidence": "LOW"}],
        )
        enriched = apply_meta_analysis([finding], meta_result)
        assert enriched[0].details is not None
        assert enriched[0].details["meta_false_positive"] is False

    def test_unclassified_finding_gets_meta_reviewed(self):
        """A finding not in validated or FP lists gets meta_reviewed=True."""
        findings = [_make_finding()]
        meta_result = MetaAnalysisResult()
        enriched = apply_meta_analysis(findings, meta_result)
        assert enriched[0].details["meta_reviewed"] is True
        assert enriched[0].details["meta_false_positive"] is False

    def test_multiple_analyzers_all_enriched(self):
        """Findings from different analyzers are all enriched correctly."""
        findings = [
            _make_finding(analyzer="YARA", summary="YARA finding"),
            _make_finding(analyzer="LLM", summary="LLM finding"),
            _make_finding(analyzer="API", summary="API finding"),
        ]
        meta_result = MetaAnalysisResult(
            validated_findings=[
                {"_index": 0, "confidence": "HIGH"},
                {"_index": 1, "confidence": "MEDIUM"},
            ],
            false_positives=[
                {"_index": 2, "reason": "API false alarm"},
            ],
            priority_order=[0, 1],
        )
        enriched = apply_meta_analysis(findings, meta_result)

        assert len(enriched) == 3
        assert enriched[0].analyzer == "YARA"
        assert enriched[0].details["meta_validated"] is True
        assert enriched[0].details["meta_priority"] == 1

        assert enriched[1].analyzer == "LLM"
        assert enriched[1].details["meta_validated"] is True
        assert enriched[1].details["meta_priority"] == 2

        assert enriched[2].analyzer == "API"
        assert enriched[2].details["meta_false_positive"] is True
        assert enriched[2].details["meta_reason"] == "API false alarm"


# ---------------------------------------------------------------------------
# MetaAnalyzer — Cover Remaining Findings (follow-up)
# ---------------------------------------------------------------------------

class TestCoverRemainingFindings:
    """Tests for the follow-up pass on uncovered findings."""

    @pytest.mark.asyncio
    @patch("mcpscanner.core.analyzers.meta_analyzer.acompletion")
    async def test_no_followup_when_all_covered(self, mock_completion):
        """No follow-up LLM call when all findings are classified."""
        mock_completion.return_value = _mock_llm_response({
            "validated_findings": [{"_index": 0}, {"_index": 1}],
            "false_positives": [],
            "missed_threats": [],
            "priority_order": [0, 1],
            "correlations": [],
            "recommendations": [],
            "overall_risk_assessment": {"risk_level": "MEDIUM"},
        })

        analyzer = MetaAnalyzer(_make_config())
        findings = [_make_finding(), _make_finding(analyzer="LLM")]
        await analyzer.analyze_findings(
            findings=findings,
            analyzers_used=["YARA", "LLM"],
            entity_context={"type": "tool", "name": "test"},
        )

        # Only the initial call, no follow-up
        assert mock_completion.call_count == 1

    @pytest.mark.asyncio
    @patch("mcpscanner.core.analyzers.meta_analyzer.acompletion")
    async def test_followup_for_uncovered_findings(self, mock_completion):
        """A follow-up call is made for findings not covered in first pass."""
        initial_response = _mock_llm_response({
            "validated_findings": [{"_index": 0}],
            "false_positives": [],
            "missed_threats": [],
            "priority_order": [0],
            "correlations": [],
            "recommendations": [],
            "overall_risk_assessment": {"risk_level": "MEDIUM"},
        })
        followup_response = _mock_llm_response({
            "validated_findings": [{"_index": 1, "confidence": "LOW"}],
            "false_positives": [],
        })
        mock_completion.side_effect = [initial_response, followup_response]

        analyzer = MetaAnalyzer(_make_config())
        findings = [_make_finding(), _make_finding(analyzer="LLM")]
        result = await analyzer.analyze_findings(
            findings=findings,
            analyzers_used=["YARA", "LLM"],
            entity_context={"type": "tool", "name": "test"},
        )

        assert mock_completion.call_count == 2
        all_indices = {vf["_index"] for vf in result.validated_findings}
        assert 0 in all_indices
        assert 1 in all_indices
