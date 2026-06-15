# Copyright 2026 Cisco Systems, Inc. and its affiliates
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

"""Tests for AlignmentLLMClient's Bedrock authentication and routing.

Mirrors the auth tiers documented on ``LLMAnalyzer`` and asserts they
also apply to the behavioral path:

  1. Non-Bedrock providers REQUIRE an api_key (regression guard).
  2. Bedrock + api_key uses the api_key.
  3. Bedrock + bearer token (no api_key) uses the bearer token.
  4. Bedrock alone leaves api_key unset so litellm/boto3 resolve via
     the AWS provider chain (profile / IAM / session token).

Per-request, AWS-specific routing parameters (``aws_region_name``,
``aws_session_token``, ``aws_profile_name``) are forwarded to
``acompletion`` only for Bedrock requests.
"""

from __future__ import annotations

from unittest.mock import patch, AsyncMock

import pytest

from mcpscanner.config.config import Config
from mcpscanner.core.analyzers.behavioral.alignment.alignment_llm_client import (
    AlignmentLLMClient,
)


def _bedrock_config(**overrides) -> Config:
    """Construct a Config that targets a Bedrock model by default."""
    base = {
        "llm_model": "bedrock/us.anthropic.claude-haiku-4-5-20250929-v1:0",
        "aws_region_name": "us-west-2",
    }
    base.update(overrides)
    return Config(**base)


def _non_bedrock_config(**overrides) -> Config:
    base = {"llm_model": "gpt-4o", "llm_provider_api_key": "sk-test"}
    base.update(overrides)
    return Config(**base)


# ---------------------------------------------------------------------------
# __init__ — auth strategy by provider
# ---------------------------------------------------------------------------


class TestAlignmentLLMClientInitAuth:
    """Cover the four init-time auth tiers."""

    def test_non_bedrock_without_api_key_raises(self):
        """Regression: non-Bedrock providers still require an api_key."""
        cfg = Config(llm_model="gpt-4o", llm_provider_api_key=None)
        with pytest.raises(ValueError, match="LLM provider API key is required"):
            AlignmentLLMClient(cfg)

    def test_non_bedrock_with_api_key_uses_it(self):
        cfg = _non_bedrock_config(llm_provider_api_key="sk-prod")
        client = AlignmentLLMClient(cfg)
        assert client._api_key == "sk-prod"
        # Non-Bedrock requests must NOT receive AWS routing knobs.
        assert client._aws_region is None
        assert client._aws_session_token is None
        assert client._aws_profile_name is None

    def test_bedrock_with_api_key_prefers_api_key(self):
        cfg = _bedrock_config(
            llm_provider_api_key="bedrock-api-key",
            aws_bearer_token_bedrock="bearer-should-be-ignored",
        )
        client = AlignmentLLMClient(cfg)
        # api_key wins over bearer token (matches LLMAnalyzer ordering).
        assert client._api_key == "bedrock-api-key"
        assert client._aws_region == "us-west-2"

    def test_bedrock_with_bearer_token_only_uses_bearer(self):
        cfg = _bedrock_config(
            aws_bearer_token_bedrock="long-lived-bedrock-bearer-token-1234",
        )
        client = AlignmentLLMClient(cfg)
        assert client._api_key == "long-lived-bedrock-bearer-token-1234"
        assert client._aws_region == "us-west-2"

    def test_bedrock_with_no_credentials_uses_provider_chain(self):
        """Bedrock + no api_key + no bearer token → IAM / profile / session.

        This is the case that used to raise. The behavioral path is now
        on parity with LLMAnalyzer.
        """
        cfg = _bedrock_config()
        # Should not raise.
        client = AlignmentLLMClient(cfg)
        assert client._api_key is None
        assert client._aws_region == "us-west-2"

    def test_bedrock_session_and_profile_stored(self):
        cfg = _bedrock_config(
            aws_session_token="STS-TOKEN-XYZ",
            aws_profile_name="prod-bedrock",
        )
        client = AlignmentLLMClient(cfg)
        assert client._aws_session_token == "STS-TOKEN-XYZ"
        assert client._aws_profile_name == "prod-bedrock"


# ---------------------------------------------------------------------------
# _make_llm_request — request-time parameter forwarding
# ---------------------------------------------------------------------------


def _stub_acompletion_response():
    """Build a minimal litellm-shaped response object for tests."""
    msg = type("Msg", (), {"content": '{"is_malicious": false}'})()
    choice = type("Choice", (), {"message": msg})()
    return type("Resp", (), {"choices": [choice]})()


class TestAlignmentLLMClientRequestForwarding:
    """Validate the kwargs sent to ``acompletion`` per provider."""

    @pytest.mark.asyncio
    async def test_non_bedrock_request_omits_aws_kwargs(self):
        cfg = _non_bedrock_config()
        client = AlignmentLLMClient(cfg)

        with patch(
            "mcpscanner.core.analyzers.behavioral.alignment."
            "alignment_llm_client.acompletion",
            new=AsyncMock(return_value=_stub_acompletion_response()),
        ) as mocked:
            await client._make_llm_request("hello")

        kwargs = mocked.await_args.kwargs
        assert kwargs["api_key"] == "sk-test"
        # AWS routing knobs MUST NOT leak into non-Bedrock requests.
        assert "aws_region_name" not in kwargs
        assert "aws_session_token" not in kwargs
        assert "aws_profile_name" not in kwargs

    @pytest.mark.asyncio
    async def test_bedrock_with_iam_omits_api_key(self):
        """Bedrock + AWS provider chain must reach litellm with no api_key."""
        cfg = _bedrock_config()
        client = AlignmentLLMClient(cfg)

        with patch(
            "mcpscanner.core.analyzers.behavioral.alignment."
            "alignment_llm_client.acompletion",
            new=AsyncMock(return_value=_stub_acompletion_response()),
        ) as mocked:
            await client._make_llm_request("hello")

        kwargs = mocked.await_args.kwargs
        # Critical: api_key absent so litellm/boto3 fall through to IAM.
        assert "api_key" not in kwargs
        assert kwargs["aws_region_name"] == "us-west-2"

    @pytest.mark.asyncio
    async def test_bedrock_with_bearer_token_forwards_as_api_key(self):
        cfg = _bedrock_config(aws_bearer_token_bedrock="bearer-xyz-abcdefghij")
        client = AlignmentLLMClient(cfg)

        with patch(
            "mcpscanner.core.analyzers.behavioral.alignment."
            "alignment_llm_client.acompletion",
            new=AsyncMock(return_value=_stub_acompletion_response()),
        ) as mocked:
            await client._make_llm_request("hello")

        kwargs = mocked.await_args.kwargs
        assert kwargs["api_key"] == "bearer-xyz-abcdefghij"
        assert kwargs["aws_region_name"] == "us-west-2"

    @pytest.mark.asyncio
    async def test_bedrock_session_and_profile_forwarded(self):
        cfg = _bedrock_config(
            aws_session_token="STS-TOKEN-XYZ",
            aws_profile_name="prod-bedrock",
        )
        client = AlignmentLLMClient(cfg)

        with patch(
            "mcpscanner.core.analyzers.behavioral.alignment."
            "alignment_llm_client.acompletion",
            new=AsyncMock(return_value=_stub_acompletion_response()),
        ) as mocked:
            await client._make_llm_request("hello")

        kwargs = mocked.await_args.kwargs
        assert kwargs["aws_session_token"] == "STS-TOKEN-XYZ"
        assert kwargs["aws_profile_name"] == "prod-bedrock"

    @pytest.mark.asyncio
    async def test_request_disables_json_mode_for_azure(self):
        """The Azure exemption from LLM-side JSON mode must still apply."""
        cfg = Config(
            llm_model="azure/gpt-4",
            llm_provider_api_key="key",
            llm_api_version="2024-02-15-preview",
        )
        client = AlignmentLLMClient(cfg)

        with patch(
            "mcpscanner.core.analyzers.behavioral.alignment."
            "alignment_llm_client.acompletion",
            new=AsyncMock(return_value=_stub_acompletion_response()),
        ) as mocked:
            await client._make_llm_request("hello")

        kwargs = mocked.await_args.kwargs
        assert "response_format" not in kwargs
        assert kwargs["api_version"] == "2024-02-15-preview"


# ---------------------------------------------------------------------------
# Prompt-length threshold warning — must consider system + user combined.
# ---------------------------------------------------------------------------


class TestPromptLengthThresholdWarning:
    """Lock the behaviour reviewer ihabler asked for: the
    ``"Large prompt detected"`` warning must trip on the *combined*
    user+system payload, not just the user-role string.

    Pre-PR the user role carried the entire 73 KB framework template, so
    ``len(prompt)`` alone routinely crossed the threshold. Post-PR the
    bulk lives in ``system_prompt`` and ``len(prompt)`` is ~3 KB; if the
    threshold check stayed user-only the warning would silently never
    fire again. These tests prevent that regression.
    """

    @pytest.mark.asyncio
    async def test_warns_when_system_alone_exceeds_threshold(self, caplog):
        """The exact reviewer scenario: small user payload, huge system
        template. The warning MUST still fire because the LLM sees both.
        """
        from mcpscanner.config.constants import MCPScannerConstants

        cfg = _non_bedrock_config()
        client = AlignmentLLMClient(cfg)

        small_user = "evidence: {}"  # well below threshold on its own
        big_system = "X" * (MCPScannerConstants.PROMPT_LENGTH_THRESHOLD + 50)

        with patch(
            "mcpscanner.core.analyzers.behavioral.alignment."
            "alignment_llm_client.acompletion",
            new=AsyncMock(return_value=_stub_acompletion_response()),
        ), caplog.at_level("WARNING"):
            await client.verify_alignment(small_user, system_prompt=big_system)

        warning_messages = [
            r.getMessage() for r in caplog.records if r.levelname == "WARNING"
        ]
        assert any(
            "Large prompt detected" in m for m in warning_messages
        ), f"Expected combined-length threshold warning; got: {warning_messages}"
        # The message must surface both halves so reviewers can see
        # which side dominates without having to re-derive lengths.
        joined = " ".join(warning_messages)
        assert f"user={len(small_user)}" in joined
        assert f"system={len(big_system)}" in joined

    @pytest.mark.asyncio
    async def test_no_warning_when_combined_under_threshold(self, caplog):
        """Both halves small -> no warning. Sanity check the new combined
        check doesn't over-warn on routine alignment calls."""
        cfg = _non_bedrock_config()
        client = AlignmentLLMClient(cfg)

        with patch(
            "mcpscanner.core.analyzers.behavioral.alignment."
            "alignment_llm_client.acompletion",
            new=AsyncMock(return_value=_stub_acompletion_response()),
        ), caplog.at_level("WARNING"):
            await client.verify_alignment("u" * 1000, system_prompt="s" * 1000)

        warning_messages = [
            r.getMessage() for r in caplog.records if r.levelname == "WARNING"
        ]
        assert not any(
            "Large prompt detected" in m for m in warning_messages
        ), f"Unexpected threshold warning: {warning_messages}"

    @pytest.mark.asyncio
    async def test_warns_when_user_alone_exceeds_threshold_legacy_shape(
        self, caplog
    ):
        """Legacy ``verify_alignment(prompt)`` (no ``system_prompt``)
        callers must keep their warning. With ``system_length=0`` the
        combined check degenerates to user-only, matching the pre-PR
        behaviour."""
        from mcpscanner.config.constants import MCPScannerConstants

        cfg = _non_bedrock_config()
        client = AlignmentLLMClient(cfg)
        big_user = "Y" * (MCPScannerConstants.PROMPT_LENGTH_THRESHOLD + 100)

        with patch(
            "mcpscanner.core.analyzers.behavioral.alignment."
            "alignment_llm_client.acompletion",
            new=AsyncMock(return_value=_stub_acompletion_response()),
        ), caplog.at_level("WARNING"):
            await client.verify_alignment(big_user)

        warning_messages = [
            r.getMessage() for r in caplog.records if r.levelname == "WARNING"
        ]
        assert any(
            "Large prompt detected" in m for m in warning_messages
        ), f"Legacy shape lost its threshold warning: {warning_messages}"


# ---------------------------------------------------------------------------
# Scanner gate parity (no separate file because the test is one assertion).
# ---------------------------------------------------------------------------


class TestScannerBedrockBehavioralGate:
    """Scanner.behavioral_analyzer should initialize for Bedrock-only configs."""

    def test_scanner_initializes_behavioral_with_bedrock_only(self):
        from mcpscanner.core.scanner import Scanner

        cfg = _bedrock_config()  # no api_key, no bearer token
        scanner = Scanner(cfg)
        # Used to be None on main; now mirrors the LLM analyzer gate.
        assert scanner._behavioral_analyzer is not None

    def test_scanner_skips_behavioral_when_no_credentials_for_non_bedrock(self):
        from mcpscanner.core.scanner import Scanner

        cfg = Config(llm_model="gpt-4o")  # no api key, non-Bedrock
        scanner = Scanner(cfg)
        assert scanner._behavioral_analyzer is None
