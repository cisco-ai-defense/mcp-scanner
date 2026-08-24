# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Integration tests: behavioral CLI --raw must surface findings."""

import json
import os
import tempfile
from io import StringIO
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcpscanner.cli import _build_behavioral_results, main
from mcpscanner.config import Config
from mcpscanner.core.analyzers.base import SecurityFinding
from mcpscanner.core.analyzers.behavioral import BehavioralCodeAnalyzer


@pytest.mark.asyncio
async def test_raw_cli_output_when_analyzed_functions_cleared_after_scan(capsys):
    """Reproduce the reported bug: findings exist, analyzed_functions empty, --raw []."""
    mcp_code = '''
import mcp

@mcp.tool()
def leaky(path: str) -> str:
    """Only reads local files."""
    return open(path).read()
'''
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(mcp_code)
        f.flush()
        temp_path = f.name

    try:
        mock_analysis = {
            "threat_name": "DATA EXFILTRATION",
            "description_claims": "Only reads local files",
            "actual_behavior": "Opens arbitrary path",
            "security_implications": "Path traversal / exfil risk",
            "threat_vulnerability_classification": "THREAT",
        }

        async def fake_analyze(self, content, context):
            finding = SecurityFinding(
                severity="HIGH",
                summary="Line 5: DATA EXFILTRATION - mismatch",
                threat_category="DATA EXFILTRATION",
                analyzer="Behavioral",
                details={
                    "function_name": "leaky",
                    "source_file": temp_path,
                    "decorator_type": "@mcp.tool",
                    "line_number": 5,
                    "threat_vulnerability_classification": "THREAT",
                },
            )
            # Simulate the bug: findings populated, side-channel empty.
            self.analyzed_functions = []
            return [finding]

        with patch.object(
            BehavioralCodeAnalyzer, "analyze", fake_analyze
        ), patch.dict(
            os.environ,
            {"MCP_SCANNER_LLM_API_KEY": "test-key", "MCP_SCANNER_LLM_PROVIDER": "openai"},
            clear=False,
        ):
            test_args = [
                "mcp-scanner",
                "behavioral",
                temp_path,
                "--raw",
            ]
            with patch("sys.argv", test_args):
                await main()

        captured = capsys.readouterr()
        assert captured.out.strip(), "expected JSON on stdout"
        payload = json.loads(captured.out)
        assert isinstance(payload, list)
        assert len(payload) >= 1, f"expected findings in --raw output, got {payload!r}"
        names = {row.get("tool_name") for row in payload}
        assert "leaky" in names
        unsafe = [r for r in payload if not r.get("is_safe")]
        assert unsafe, "expected at least one unsafe tool in raw output"
        assert unsafe[0]["findings"]["behavioral_analyzer"]["severity"] == "HIGH"
    finally:
        os.unlink(temp_path)


def test_build_and_threat_filter_non_raw_when_analyzed_functions_empty():
    """Non-raw output must keep THREAT rows even without analyzed_functions."""
    finding = SecurityFinding(
        severity="HIGH",
        summary="Line 1: DATA EXFILTRATION",
        threat_category="DATA EXFILTRATION",
        analyzer="Behavioral",
        details={
            "function_name": "exfil",
            "source_file": "/tmp/pkg/tool.py",
            "line_number": 1,
        },
    )
    analyzer = MagicMock()
    analyzer.analyzed_functions = []

    results = _build_behavioral_results(analyzer, [finding], source_path="/tmp/pkg")
    filtered = []
    for result in results:
        if result.get("is_safe", False):
            filtered.append(result)
            continue
        classification = (
            result.get("findings", {})
            .get("behavioral_analyzer", {})
            .get("threat_vulnerability_classification")
            or ""
        ).upper()
        if classification == "THREAT":
            filtered.append(result)

    assert len(filtered) == 1
    assert filtered[0]["tool_name"] == "exfil"
