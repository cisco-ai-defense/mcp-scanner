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

"""Unit tests for first-class AWS Bedrock (IAM/SSO) activation of the LLM analyzer.

These cover the two halves of the Bedrock-without-an-API-key fix:

1. The boto3 pre-flight (``ensure_bedrock_dependencies``) that turns litellm's
   opaque ``No module named 'boto3'`` into an actionable error.
2. The CLI ``static`` gate that activates the LLM analyzer for ``bedrock/*``
   models authenticating via the AWS credential chain, without requiring a
   (placeholder) ``MCP_SCANNER_LLM_API_KEY``.
"""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcpscanner.config import Config
from mcpscanner.core.analyzers.llm_analyzer import LLMAnalyzer
from mcpscanner.utils import bedrock as bedrock_utils
from mcpscanner.utils.bedrock import (
    BedrockDependencyError,
    ensure_bedrock_dependencies,
    is_bedrock_model,
)

_BEDROCK_MODEL = "bedrock/eu.anthropic.claude-sonnet-4-5-20250929-v1:0"


class TestIsBedrockModel:
    def test_recognises_bedrock_models(self):
        assert is_bedrock_model(_BEDROCK_MODEL) is True
        assert is_bedrock_model("bedrock/anthropic.claude-3-sonnet") is True

    def test_rejects_non_bedrock_and_empty(self):
        assert is_bedrock_model("gpt-4o") is False
        assert is_bedrock_model("openai/gpt-4o") is False
        assert is_bedrock_model("") is False
        assert is_bedrock_model(None) is False


class TestEnsureBedrockDependencies:
    def test_noop_for_non_bedrock_even_without_boto3(self):
        # Non-Bedrock models must never require boto3, regardless of whether it
        # is importable.
        with patch.object(bedrock_utils.importlib.util, "find_spec", return_value=None):
            ensure_bedrock_dependencies("openai/gpt-4o")  # must not raise

    def test_raises_actionable_error_when_boto3_missing(self):
        with patch.object(bedrock_utils.importlib.util, "find_spec", return_value=None):
            with pytest.raises(BedrockDependencyError) as exc:
                ensure_bedrock_dependencies(_BEDROCK_MODEL)
        msg = str(exc.value)
        assert "boto3" in msg
        assert "bedrock" in msg.lower()

    def test_passes_when_boto3_present(self):
        with patch.object(
            bedrock_utils.importlib.util, "find_spec", return_value=object()
        ):
            ensure_bedrock_dependencies(_BEDROCK_MODEL)  # must not raise


class TestLLMAnalyzerBedrockPreflight:
    def test_llm_analyzer_surfaces_missing_boto3(self):
        config = Config(llm_model=_BEDROCK_MODEL, aws_region_name="eu-central-1")
        with patch.object(bedrock_utils.importlib.util, "find_spec", return_value=None):
            with pytest.raises(BedrockDependencyError):
                LLMAnalyzer(config)

    def test_llm_analyzer_activates_without_api_key_for_bedrock(self):
        # No API key + Bedrock model + AWS creds = analyzer should construct and
        # not pass an api_key down to litellm.
        config = Config(llm_model=_BEDROCK_MODEL, aws_region_name="eu-central-1")
        analyzer = LLMAnalyzer(config)
        assert analyzer._api_key is None
        assert analyzer._aws_region == "eu-central-1"


class TestCLIStaticBedrockGate:
    """The ``static`` subcommand must activate the LLM analyzer for Bedrock+IAM."""

    @pytest.fixture
    def tools_json_file(self, tmp_path):
        data = {
            "tools": [
                {
                    "name": "safe_calculator",
                    "description": "Adds two numbers",
                    "inputSchema": {"type": "object"},
                }
            ]
        }
        file_path = tmp_path / "tools.json"
        file_path.write_text(json.dumps(data))
        return str(file_path)

    @pytest.mark.asyncio
    async def test_bedrock_model_activates_llm_without_api_key(
        self, tools_json_file, capsys, monkeypatch
    ):
        from mcpscanner.cli import main

        monkeypatch.setenv("MCP_SCANNER_LLM_MODEL", _BEDROCK_MODEL)
        monkeypatch.setenv("AWS_REGION", "eu-central-1")
        monkeypatch.delenv("MCP_SCANNER_LLM_API_KEY", raising=False)

        fake_llm = MagicMock(name="LLMAnalyzerInstance")
        llm_cls = MagicMock(return_value=fake_llm)

        fake_static = MagicMock()
        fake_static.scan_tools_file = AsyncMock(return_value=[])

        test_args = [
            "mcp-scanner",
            "--analyzers",
            "llm",
            "static",
            "--tools",
            tools_json_file,
        ]

        with (
            patch("sys.argv", test_args),
            patch("mcpscanner.cli.LLMAnalyzer", llm_cls),
            patch("mcpscanner.cli.StaticAnalyzer", return_value=fake_static),
        ):
            await main()

        # The LLM analyzer must have been constructed despite no API key...
        llm_cls.assert_called_once()
        # ...and the skip warning must NOT be emitted.
        captured = capsys.readouterr()
        assert "LLM analyzer requested but MCP_SCANNER_LLM_API_KEY" not in captured.err

    @pytest.mark.asyncio
    async def test_non_bedrock_without_api_key_still_warns_and_skips(
        self, tools_json_file, capsys, monkeypatch
    ):
        from mcpscanner.cli import main

        monkeypatch.setenv("MCP_SCANNER_LLM_MODEL", "openai/gpt-4o")
        monkeypatch.delenv("MCP_SCANNER_LLM_API_KEY", raising=False)

        llm_cls = MagicMock()

        test_args = [
            "mcp-scanner",
            "--analyzers",
            "llm",
            "static",
            "--tools",
            tools_json_file,
        ]

        with patch("sys.argv", test_args), patch("mcpscanner.cli.LLMAnalyzer", llm_cls):
            with pytest.raises(SystemExit):
                # No analyzers available -> CLI exits(1).
                await main()

        llm_cls.assert_not_called()
        captured = capsys.readouterr()
        assert "LLM analyzer requested but MCP_SCANNER_LLM_API_KEY" in captured.err
