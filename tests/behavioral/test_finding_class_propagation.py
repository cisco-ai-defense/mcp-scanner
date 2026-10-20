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

"""finding_class must survive the production finding factories.

AlignmentResponseValidator normalizes the field, but Python and JS scans
build SecurityFinding.details themselves. These tests go through
``_analyze_source_code`` so a factory that drops the field fails.
"""

import os
import tempfile
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcpscanner.config.config import Config
from mcpscanner.core.analyzers.behavioral.code_analyzer import BehavioralCodeAnalyzer
from mcpscanner.core.analyzers.behavioral.js_code_analyzer import (
    JSBehavioralCodeAnalyzer,
)

_ONE_TOOL = '''
import mcp

@mcp.tool()
def read_file(path: str) -> str:
    """Read a local file."""
    return path
'''

_TWO_TOOLS = '''
import mcp

@mcp.tool()
def echo(text: str) -> str:
    """Return the text."""
    return text

@mcp.tool()
def add(a: float, b: float) -> float:
    """Add two numbers."""
    return a + b
'''


def _analysis(declared):
    data = {
        "threat_name": "DATA EXFILTRATION",
        "description_claims": "reads a file",
        "actual_behavior": "posts the file",
        "threat_vulnerability_classification": "VULNERABILITY",
    }
    if declared is not _MISSING:
        data["finding_class"] = declared
    return data


class _Missing:
    pass


_MISSING = _Missing()


def _ctx(name):
    ctx = MagicMock()
    ctx.name = name
    ctx.line_number = 1
    ctx.decorator_types = ["tool"]
    ctx.docstring = ""
    ctx.has_subprocess_calls = False
    ctx.reachable_functions = []
    ctx.parameters = []
    ctx.source = "return 1"
    ctx.line_count = 1
    return ctx


def _mismatch_classes(findings):
    return [
        (f.details or {}).get("finding_class")
        for f in findings
        if f.severity != "SAFE"
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "declared,expected",
    [
        ("CAPABILITY_RISK", "CAPABILITY_RISK"),
        ("capability risk", "CAPABILITY_RISK"),
        (_MISSING, "UNSPECIFIED"),
    ],
)
async def test_python_individual_path_keeps_finding_class(declared, expected):
    analyzer = BehavioralCodeAnalyzer(Config(llm_provider_api_key="test-key"))
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as handle:
        handle.write(_ONE_TOOL)
        path = handle.name
    try:
        with patch.object(
            analyzer.alignment_orchestrator,
            "check_alignment",
            new_callable=AsyncMock,
        ) as individual, patch.object(
            analyzer.alignment_orchestrator,
            "check_alignment_batch",
            new_callable=AsyncMock,
        ) as batched:
            individual.return_value = (_analysis(declared), _ctx("read_file"))
            findings = await analyzer._analyze_source_code(
                _ONE_TOOL, {"file_path": path, "use_batching": False}
            )
        batched.assert_not_awaited()
        individual.assert_awaited()
    finally:
        os.unlink(path)

    assert _mismatch_classes(findings) == [expected]
    mismatch = next(f for f in findings if f.severity != "SAFE")
    assert mismatch.details["threat_vulnerability_classification"] == "VULNERABILITY"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "declared,expected",
    [
        ("MALICIOUS_BEHAVIOR", "MALICIOUS_BEHAVIOR"),
        ("Malicious-Behavior", "MALICIOUS_BEHAVIOR"),
        (_MISSING, "UNSPECIFIED"),
    ],
)
async def test_python_batch_path_keeps_finding_class(declared, expected):
    analyzer = BehavioralCodeAnalyzer(Config(llm_provider_api_key="test-key"))
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as handle:
        handle.write(_TWO_TOOLS)
        path = handle.name
    try:
        with patch.object(
            analyzer.alignment_orchestrator,
            "check_alignment_batch",
            new_callable=AsyncMock,
        ) as batched, patch.object(
            analyzer.alignment_orchestrator,
            "check_alignment",
            new_callable=AsyncMock,
        ) as individual:
            batched.return_value = [
                (_analysis(declared), _ctx("echo")),
                (_analysis(declared), _ctx("add")),
            ]
            findings = await analyzer._analyze_source_code(
                _TWO_TOOLS, {"file_path": path}
            )
        individual.assert_not_awaited()
        batched.assert_awaited()
    finally:
        os.unlink(path)

    assert _mismatch_classes(findings) == [expected, expected]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "declared,expected",
    [
        ("DOCUMENTATION_MISMATCH", "DOCUMENTATION_MISMATCH"),
        ("documentation mismatch", "DOCUMENTATION_MISMATCH"),
        (_MISSING, "UNSPECIFIED"),
    ],
)
async def test_js_individual_path_keeps_finding_class(declared, expected):
    analyzer = JSBehavioralCodeAnalyzer(Config(llm_provider_api_key="test-key"))
    with patch(
        "mcpscanner.core.static_analysis.native_analyzer.NativeAnalyzer"
    ) as native, patch.object(
        analyzer.alignment_orchestrator,
        "check_alignment",
        new_callable=AsyncMock,
    ) as individual, patch.object(
        analyzer.alignment_orchestrator,
        "check_alignment_batch",
        new_callable=AsyncMock,
    ) as batched:
        native.return_value.extract_mcp_capability_contexts.return_value = [
            _ctx("echo")
        ]
        individual.return_value = (_analysis(declared), _ctx("echo"))
        findings = await analyzer._analyze_source_code(
            "export {}", "server.ts", {"use_batching": False}
        )
    batched.assert_not_awaited()
    individual.assert_awaited()
    assert _mismatch_classes(findings) == [expected]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "declared,expected",
    [
        ("CAPABILITY_RISK", "CAPABILITY_RISK"),
        ("capability-risk", "CAPABILITY_RISK"),
        (_MISSING, "UNSPECIFIED"),
    ],
)
async def test_js_batch_path_keeps_finding_class(declared, expected):
    analyzer = JSBehavioralCodeAnalyzer(Config(llm_provider_api_key="test-key"))
    with patch(
        "mcpscanner.core.static_analysis.native_analyzer.NativeAnalyzer"
    ) as native, patch.object(
        analyzer.alignment_orchestrator,
        "check_alignment_batch",
        new_callable=AsyncMock,
    ) as batched, patch.object(
        analyzer.alignment_orchestrator,
        "check_alignment",
        new_callable=AsyncMock,
    ) as individual:
        native.return_value.extract_mcp_capability_contexts.return_value = [
            _ctx("echo"),
            _ctx("add"),
        ]
        batched.return_value = [
            (_analysis(declared), _ctx("echo")),
            (_analysis(declared), _ctx("add")),
        ]
        findings = await analyzer._analyze_source_code("export {}", "server.ts", {})
    individual.assert_not_awaited()
    batched.assert_awaited()
    assert _mismatch_classes(findings) == [expected, expected]
