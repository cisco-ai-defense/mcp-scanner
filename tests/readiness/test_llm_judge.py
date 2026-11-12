# Copyright 2025 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for ReadinessLLMJudge LiteLLM request shaping."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcpscanner.core.analyzers.readiness.llm_judge import ReadinessLLMJudge
from mcpscanner.core.analyzers.readiness.readiness_analyzer import ReadinessAnalyzer


def _mock_llm_response(body: dict) -> MagicMock:
    mock_response = MagicMock()
    mock_response.choices = [MagicMock()]
    mock_response.choices[0].message.content = json.dumps(body)
    return mock_response


class TestReadinessLLMJudgeRequestShape:
    @pytest.mark.asyncio
    @patch("mcpscanner.core.analyzers.readiness.llm_judge.acompletion")
    async def test_run_evaluation_applies_gpt5_constraints(self, mock_completion):
        mock_completion.return_value = _mock_llm_response(
            {"readiness_analysis": {}}
        )
        judge = ReadinessLLMJudge(
            model="openai/gpt-5.6-terra",
            api_key="test-key",
        )
        await judge._run_evaluation('{"name": "demo_tool"}')

        kwargs = mock_completion.call_args.kwargs
        assert kwargs["drop_params"] is True
        assert kwargs["model"] == "openai/gpt-5.6-terra"
        assert kwargs["temperature"] == 1
        assert "max_completion_tokens" in kwargs
        assert "max_tokens" not in kwargs

    def test_unusable_response_is_not_a_clean_pass(self):
        judge = ReadinessLLMJudge(model="openai/gpt-4o", api_key="test-key")
        findings = judge._results_to_findings(
            {
                "error": "Failed to parse LLM response",
                "raw": "secret tool text powershell",
            },
            "demo_tool",
        )
        assert len(findings) == 1
        assert findings[0].threat_category == "ANALYZER INFRASTRUCTURE"
        rendered = json.dumps(findings[0].details) + findings[0].summary
        assert "secret tool text" not in rendered
        assert "powershell" not in rendered


class TestReadinessJudgeFailure:
    @pytest.mark.asyncio
    async def test_analyze_keeps_a_failed_judge_incomplete(self):
        analyzer = ReadinessAnalyzer()

        class Boom:
            def is_available(self):
                return True

            async def analyze(self, tool_definition, tool_name=None):
                raise RuntimeError("provider down secret")

        analyzer._llm_judge = Boom()
        findings = await analyzer.analyze(
            '{"name": "plain", "description": "An ordinary tool with one purpose"}',
            {"tool_name": "plain"},
        )
        rendered = " ".join(finding.summary for finding in findings)
        assert any(
            finding.threat_category == "ANALYZER INFRASTRUCTURE"
            for finding in findings
        )
        assert "provider down secret" not in rendered
        assert all(
            finding.details.get("is_production_ready") is not True
            for finding in findings
        )
