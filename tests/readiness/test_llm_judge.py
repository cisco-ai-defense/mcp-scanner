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
