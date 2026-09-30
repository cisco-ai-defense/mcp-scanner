# Copyright 2025 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Apple Foundation Models provider wiring."""

import asyncio
import sys
import types

import pytest

from mcpscanner.config.config import Config
from mcpscanner.core.analyzers.behavioral.alignment.alignment_llm_client import (
    AlignmentLLMClient,
)
from mcpscanner.core.analyzers.llm_analyzer import LLMAnalyzer
from mcpscanner.core.analyzers.readiness.llm_judge import ReadinessLLMJudge
from mcpscanner.core.analyzers.meta_analyzer import MetaAnalyzer
from mcpscanner.utils import llm_completion
from mcpscanner.utils.apple_fm import apple_fm_acompletion, is_apple_fm_model


def test_apple_fm_prefix() -> None:
    assert is_apple_fm_model("apple-fm/system") is True
    assert is_apple_fm_model("APPLE-FM/system") is True
    assert is_apple_fm_model("gpt-4o") is False
    assert is_apple_fm_model(None) is False


def test_apple_fm_analyzers_do_not_require_an_api_key() -> None:
    config = Config(llm_model="apple-fm/system", llm_provider_api_key=None)
    assert LLMAnalyzer(config)._api_key is None
    assert MetaAnalyzer(config)._api_key is None
    assert AlignmentLLMClient(config)._api_key is None


def test_readiness_judge_is_available_without_an_api_key(monkeypatch) -> None:
    monkeypatch.setattr(
        "mcpscanner.core.analyzers.readiness.llm_judge.apple_fm_runtime_status",
        lambda: (True, ""),
    )
    judge = ReadinessLLMJudge(model="apple-fm/system", api_key=None)
    assert judge.is_available() is True
    assert judge.get_unavailable_reason() is None


def test_readiness_judge_unavailable_when_runtime_is_not(monkeypatch) -> None:
    monkeypatch.setattr(
        "mcpscanner.core.analyzers.readiness.llm_judge.apple_fm_runtime_status",
        lambda: (False, "apple-fm-sdk is not installed"),
    )
    judge = ReadinessLLMJudge(model="apple-fm/system", api_key=None)
    assert judge.is_available() is False
    assert judge.get_unavailable_reason() == "apple-fm-sdk is not installed"


def test_hosted_model_still_requires_an_api_key() -> None:
    config = Config(llm_model="gpt-4o", llm_provider_api_key=None)
    with pytest.raises(ValueError):
        LLMAnalyzer(config)


@pytest.mark.asyncio
async def test_apple_fm_completion_uses_system_model(monkeypatch) -> None:
    created = {}

    class _Session:
        def __init__(self, instructions=None):
            self.instructions = instructions
            self.prompt = None

        async def respond(self, prompt, options=None):
            self.prompt = prompt
            self.options = options
            return "on-device answer"

    class _Model:
        def is_available(self):
            return True, None

    def _language_model_session(instructions=None):
        created["session"] = _Session(instructions)
        return created["session"]

    class _Options:
        def __init__(self, temperature=None, maximum_response_tokens=None):
            self.temperature = temperature
            self.maximum_response_tokens = maximum_response_tokens

    fake = types.ModuleType("apple_fm_sdk")
    fake.SystemLanguageModel = _Model
    fake.LanguageModelSession = _language_model_session
    fake.GenerationOptions = _Options
    monkeypatch.setitem(sys.modules, "apple_fm_sdk", fake)

    response = await apple_fm_acompletion(
        model="apple-fm/system",
        messages=[
            {"role": "system", "content": "Be brief."},
            {"role": "user", "content": "Hello"},
        ],
        api_key="ignored",
        drop_params=True,
        temperature=0.0,
        max_tokens=1000,
    )
    assert response.choices[0].message.content == "on-device answer"
    assert created["session"].instructions == "Be brief."
    assert created["session"].prompt == "Hello"
    assert created["session"].options.temperature == 0.0
    assert created["session"].options.maximum_response_tokens == 1000


@pytest.mark.asyncio
async def test_dispatcher_sends_apple_fm_prefix_to_sdk(monkeypatch) -> None:
    async def _fake(**_kwargs):
        return "routed"

    monkeypatch.setattr(llm_completion, "apple_fm_acompletion", _fake)
    assert await llm_completion.acompletion(model="apple-fm/system") == "routed"


@pytest.mark.asyncio
async def test_missing_sdk_tells_the_user_how_to_install(monkeypatch) -> None:
    monkeypatch.setitem(sys.modules, "apple_fm_sdk", None)
    with pytest.raises(ImportError, match="pip install apple-fm-sdk"):
        await apple_fm_acompletion(model="apple-fm/system", messages=[])


@pytest.mark.asyncio
async def test_timeout_is_reported_as_a_timeout(monkeypatch) -> None:
    class _Model:
        def is_available(self):
            return True, None

    class _Session:
        async def respond(self, prompt, options=None):
            await asyncio.sleep(5)
            return prompt

    fake = types.ModuleType("apple_fm_sdk")
    fake.SystemLanguageModel = _Model
    fake.LanguageModelSession = lambda instructions=None: _Session()
    monkeypatch.setitem(sys.modules, "apple_fm_sdk", fake)
    with pytest.raises(TimeoutError, match="timed out after 0.01"):
        await apple_fm_acompletion(
            model="apple-fm/system",
            messages=[{"role": "user", "content": "Hello"}],
            timeout=0.01,
        )


@pytest.mark.asyncio
async def test_unavailable_model_is_an_error(monkeypatch) -> None:
    class _Model:
        def is_available(self):
            return False, "Apple Intelligence is off"

    fake = types.ModuleType("apple_fm_sdk")
    fake.SystemLanguageModel = _Model
    fake.LanguageModelSession = lambda: None
    monkeypatch.setitem(sys.modules, "apple_fm_sdk", fake)
    with pytest.raises(RuntimeError, match="Apple Intelligence is off"):
        await apple_fm_acompletion(model="apple-fm/system", messages=[])
