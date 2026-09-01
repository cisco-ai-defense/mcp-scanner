"""Tests for LiteLLM request parameter helpers."""

from mcpscanner.utils.llm_request_params import (
    apply_deterministic_sampling,
    apply_model_constraints,
)


def test_apply_deterministic_sampling_sets_zero_temperature():
    params = {"temperature": 0.1, "max_tokens": 512}
    apply_deterministic_sampling("anthropic/claude-sonnet-4", params)

    assert params["temperature"] == 0.0
    assert params["max_tokens"] == 512
    assert "top_p" not in params


def test_apply_deterministic_sampling_respects_gpt5_constraints():
    params = {"temperature": 0.1, "max_tokens": 512}
    apply_deterministic_sampling("openai/gpt-5.6-terra", params)

    assert params["temperature"] == 1
    assert params["max_completion_tokens"] == 512
    assert "max_tokens" not in params
    assert "top_p" not in params


def test_apply_model_constraints_only_for_gpt5():
    params = {"temperature": 0.0, "max_tokens": 256}
    apply_model_constraints("bedrock/us.anthropic.claude-sonnet-4", params)

    assert params == {"temperature": 0.0, "max_tokens": 256}
