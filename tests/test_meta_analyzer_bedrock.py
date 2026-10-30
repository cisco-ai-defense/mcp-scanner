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

"""Bedrock-specific request shaping for MetaAnalyzer."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from mcpscanner.config.config import Config
from mcpscanner.core.analyzers.meta_analyzer import MetaAnalyzer


def _stub_acompletion_response():
    msg = type("Msg", (), {"content": '{"false_positives": []}'})()
    choice = type("Choice", (), {"message": msg})()
    return type("Resp", (), {"choices": [choice]})()


class TestMetaAnalyzerBedrockRequest:
    @pytest.mark.asyncio
    async def test_opus_47_omits_temperature(self):
        cfg = Config(
            llm_model="bedrock/us.anthropic.claude-opus-4-7",
            aws_region_name="us-west-2",
        )
        analyzer = MetaAnalyzer(cfg)

        with patch(
            "mcpscanner.core.analyzers.meta_analyzer.acompletion",
            new=AsyncMock(return_value=_stub_acompletion_response()),
        ) as mocked:
            await analyzer._make_llm_request("system", "user")

        kwargs = mocked.await_args.kwargs
        assert "temperature" not in kwargs
        assert kwargs["aws_region_name"] == "us-west-2"

    @pytest.mark.asyncio
    async def test_sonnet_keeps_temperature(self):
        cfg = Config(
            llm_model="bedrock/us.anthropic.claude-sonnet-4-6",
            aws_region_name="us-west-2",
        )
        analyzer = MetaAnalyzer(cfg)

        with patch(
            "mcpscanner.core.analyzers.meta_analyzer.acompletion",
            new=AsyncMock(return_value=_stub_acompletion_response()),
        ) as mocked:
            await analyzer._make_llm_request("system", "user")

        kwargs = mocked.await_args.kwargs
        assert kwargs["temperature"] == analyzer._temperature
