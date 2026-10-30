# Copyright 2025 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for ReadinessLLMJudge LiteLLM request shaping."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcpscanner.core.analyzers.readiness.llm_judge import ReadinessLLMJudge


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


_FAILING_ANALYSIS = {
    "readiness_analysis": {
        "actionable_errors": {
            "is_actionable": False,
            "confidence": 0.9,
            "reasoning": "Errors give no hint",
            "suggestions": ["Return error codes"],
        }
    }
}


def _mock_text_response(text: str) -> MagicMock:
    mock_response = MagicMock()
    mock_response.choices = [MagicMock()]
    mock_response.choices[0].message.content = text
    return mock_response


class TestReadinessLLMJudgeUnreadableResponse:
    @pytest.mark.asyncio
    @patch("mcpscanner.core.analyzers.readiness.llm_judge.acompletion")
    async def test_json_wrapped_in_prose_is_parsed(self, mock_completion):
        mock_completion.return_value = _mock_text_response(
            "Here is my analysis:\n"
            + json.dumps(_FAILING_ANALYSIS)
            + "\nHope that helps!"
        )
        judge = ReadinessLLMJudge(model="openai/gpt-4o", api_key="test-key")

        findings = await judge.analyze({"name": "demo_tool"})

        assert len(findings) == 1
        assert findings[0].details["rule_id"] == "LLM-READINESS-ACTIONABLE-ERRORS"

    @pytest.mark.asyncio
    @patch("mcpscanner.core.analyzers.readiness.llm_judge.acompletion")
    async def test_unparseable_response_is_not_reported_as_clean(
        self, mock_completion
    ):
        mock_completion.return_value = _mock_text_response("I cannot evaluate this.")
        judge = ReadinessLLMJudge(model="openai/gpt-4o", api_key="test-key")

        findings = await judge.analyze({"name": "demo_tool"})

        assert len(findings) == 1
        assert findings[0].analyzer == "READINESS-LLM"
        assert findings[0].details["subject"] == "demo_tool"
        assert findings[0].details["error_kind"]

    @pytest.mark.asyncio
    @patch("mcpscanner.core.analyzers.readiness.llm_judge.acompletion")
    async def test_unrelated_object_before_analysis_is_skipped(self, mock_completion):
        mock_completion.return_value = _mock_text_response(
            'The tool is {"name": "demo_tool"}. Analysis:\n'
            + json.dumps(_FAILING_ANALYSIS)
        )
        judge = ReadinessLLMJudge(model="openai/gpt-4o", api_key="test-key")

        findings = await judge.analyze({"name": "demo_tool"})

        assert len(findings) == 1
        assert findings[0].details["rule_id"] == "LLM-READINESS-ACTIONABLE-ERRORS"

    @pytest.mark.asyncio
    @patch("mcpscanner.core.analyzers.readiness.llm_judge.acompletion")
    async def test_analysis_with_error_field_is_kept(self, mock_completion):
        mock_completion.return_value = _mock_text_response(
            "Result: " + json.dumps({**_FAILING_ANALYSIS, "error": "none"})
        )
        judge = ReadinessLLMJudge(model="openai/gpt-4o", api_key="test-key")

        findings = await judge.analyze({"name": "demo_tool"})

        assert [f.details["rule_id"] for f in findings] == [
            "LLM-READINESS-ACTIONABLE-ERRORS"
        ]

    @pytest.mark.asyncio
    @patch("mcpscanner.core.analyzers.readiness.llm_judge.acompletion")
    async def test_only_unrelated_object_is_infrastructure_error(
        self, mock_completion
    ):
        mock_completion.return_value = _mock_text_response('Tool: {"name": "x"} done')
        judge = ReadinessLLMJudge(model="openai/gpt-4o", api_key="test-key")

        findings = await judge.analyze({"name": "demo_tool"})

        assert len(findings) == 1
        assert findings[0].analyzer == "READINESS-LLM"
        assert findings[0].details["error_kind"] == "transient"
