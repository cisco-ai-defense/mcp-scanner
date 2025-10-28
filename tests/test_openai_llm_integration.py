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

"""OpenAI-backed integration tests for the LLM analyzer.

These tests exercise a real LiteLLM call using the configured OpenAI model.
They run only when the required environment variable is set:
`MCP_SCANNER_LLM_API_KEY`.
"""

import os
import pytest
from unittest.mock import patch

from mcpscanner.config import Config
from mcpscanner.core.analyzers.llm_analyzer import LLMAnalyzer


# Only skip based on whether the API key is present; still mark as integration
LLM_API_KEY_PRESENT = bool(os.environ.get("MCP_SCANNER_LLM_API_KEY"))
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not LLM_API_KEY_PRESENT,
        reason="MCP_SCANNER_LLM_API_KEY not set; skipping OpenAI integration tests.",
    ),
]


@pytest.fixture(scope="module")
def llm_analyzer():
    """Provide an LLMAnalyzer configured from environment variables.

    Requires `MCP_SCANNER_LLM_API_KEY`. Optional envs like `MCP_SCANNER_LLM_MODEL`,
    `MCP_SCANNER_LLM_BASE_URL`, and `MCP_SCANNER_LLM_API_VERSION` are honored via
    Config defaults used across the codebase.
    """
    api_key = os.environ.get("MCP_SCANNER_LLM_API_KEY")

    # Use only environment-backed configuration already supported by the app
    config = Config(
        llm_provider_api_key=api_key,
        # Other LLM parameters (model/base_url/api_version) are sourced from env via Config
    )
    return LLMAnalyzer(config)


@pytest.mark.asyncio
async def test_openai_llm_analyzer_detects_risk(llm_analyzer: LLMAnalyzer):
    """Risky tool: build prompt and ensure real LLM call returns parseable JSON."""
    tool_name = "shell_exec"
    description = (
        "Tool that executes arbitrary shell commands provided by the user using "
        "os.system with the 'command' parameter."
    )
    parameters = {
        "command": {"type": "string", "description": "The shell command to execute"}
    }

    prompt, injection = llm_analyzer._create_threat_analysis_prompt(
        tool_name, description=description, parameters=parameters
    )
    assert injection is False

    messages = [
        {
            "role": "system",
            "content": "You are a security expert analyzing MCP tools for threats. Follow the analysis framework provided.",
        },
        {"role": "user", "content": prompt},
    ]

    response = await llm_analyzer._make_llm_request(
        messages=messages, context=f"threat analysis for {tool_name}"
    )
    assert hasattr(response, "choices") and response.choices
    content = response.choices[0].message.content
    analysis = llm_analyzer._parse_response(content)
    assert isinstance(analysis, dict)


@pytest.mark.asyncio
async def test_openai_llm_analyzer_handles_invalid_api_key_gracefully():
    """Mimic case where an API key is present but invalid.

    We construct an analyzer with an invalid API key and patch the underlying
    LiteLLM call to raise an authentication-style error, then verify that the
    high-level analyze() call handles the error gracefully by returning an
    empty findings list (per implementation).
    """
    invalid_key = "sk-invalid-test-key"

    # Use zero retries to avoid repeated attempts when erroring
    analyzer = LLMAnalyzer(
        Config(
            llm_provider_api_key=invalid_key,
            llm_max_retries=0,
        )
    )

    tool_content = "Simple tool that echoes input"

    # Patch the LiteLLM acompletion call to simulate an invalid API key error
    with patch(
        "mcpscanner.core.analyzers.llm_analyzer.acompletion",
        side_effect=Exception("401 Unauthorized: invalid api key"),
    ) as mock_acompletion:
        findings = await analyzer.analyze(tool_content)

        # The analyzer should catch the error and return an empty list
        assert findings == []

        # Ensure we attempted exactly once and passed through the invalid key
        assert mock_acompletion.call_count == 1
        _, kwargs = mock_acompletion.call_args
        assert kwargs.get("api_key") == invalid_key
