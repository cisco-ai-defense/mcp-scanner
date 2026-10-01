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

"""A crashed analyzer must not produce a clean scan result."""

import asyncio
import json
import sys
from io import StringIO
from logging import StreamHandler
from types import SimpleNamespace

import pytest

from mcpscanner.api.router import (
    _convert_scanner_result_to_tool_api_result,
    _group_findings_for_api,
    scan_all_resources_endpoint,
)
from mcpscanner.cli import display_resource_results_table, display_results
from mcpscanner.core.analyzers.base import SecurityFinding
from mcpscanner.core.analyzers.meta_analyzer import MetaAnalysisResult
from mcpscanner.core.models import APIScanRequest, AnalyzerEnum, OutputFormat
from mcpscanner.core.report_generator import ReportGenerator, results_to_json
from mcpscanner.core.result import (
    ToolScanResult,
    filter_results_by_severity,
    format_results_as_json,
)
from mcpscanner.core.scanner import Scanner, logger as scanner_logger


class CleanAnalyzer:
    async def analyze(self, content, context=None):
        return []


class CrashingAnalyzer:
    async def analyze(self, content, context=None):
        raise RuntimeError("secret-token-must-not-leak")


def _scanner(api_analyzer=None, yara_analyzer=None):
    scanner = Scanner.__new__(Scanner)
    scanner._api_analyzer = api_analyzer
    scanner._yara_analyzer = yara_analyzer
    scanner._llm_analyzer = None
    scanner._readiness_analyzer = None
    scanner._prompt_defense_analyzer = None
    scanner._custom_analyzers = []
    return scanner


async def _scan_entity(scanner, entity, analyzers):
    if entity == "tool":
        tool = SimpleNamespace(
            name="example",
            description="Example tool",
            model_dump_json=lambda: json.dumps(
                {"name": "example", "description": "Example tool", "inputSchema": {}}
            ),
        )
        return await scanner._analyze_tool(tool, analyzers)
    if entity == "prompt":
        prompt = SimpleNamespace(
            name="example",
            description="Example prompt",
            model_dump_json=lambda: json.dumps(
                {"name": "example", "description": "Example prompt"}
            ),
        )
        return await scanner._analyze_prompt(prompt, analyzers)
    if entity == "resource":
        return await scanner._analyze_resource(
            resource_content="Example resource",
            resource_uri="file:///example.txt",
            resource_name="example",
            resource_description="Example resource",
            resource_mime_type="text/plain",
            analyzers=analyzers,
        )
    return await scanner._analyze_instructions(
        instructions="Example instructions",
        server_name="example",
        protocol_version="2025-06-18",
        analyzers=analyzers,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("entity", ["tool", "prompt", "resource", "instructions"])
async def test_crashed_analyzer_is_not_reported_safe(entity):
    scanner = _scanner(CleanAnalyzer(), CrashingAnalyzer())

    log_output = StringIO()
    log_handler = StreamHandler(log_output)
    scanner_logger.addHandler(log_handler)
    try:
        result = await _scan_entity(
            scanner, entity, [AnalyzerEnum.API, AnalyzerEnum.YARA]
        )
    finally:
        scanner_logger.removeHandler(log_handler)
    payload = json.loads(format_results_as_json([result]))["scan_results"][0]

    assert result.status == "partial"
    assert result.analyzers == [AnalyzerEnum.API]
    assert result.is_safe is None
    assert {error["analyzer"] for error in result.analyzer_errors} == {"YARA"}
    assert "secret-token-must-not-leak" not in json.dumps(payload)
    assert "secret-token-must-not-leak" not in log_output.getvalue()
    assert "RuntimeError" in log_output.getvalue()
    assert payload["status"] == "partial"
    assert payload["is_safe"] is None
    assert payload["findings"]["api_analyzer"]["severity"] == "SAFE"
    assert payload["findings"]["yara_analyzer"]["severity"] == "UNKNOWN"
    assert payload["findings"]["yara_analyzer"]["status"] == "error"
    assert "llm_analyzer" not in payload["findings"]
    api_findings = _group_findings_for_api(result, scanner)
    assert api_findings["api_analyzer"]["severity"] == "SAFE"
    assert api_findings["yara_analyzer"]["severity"] == "UNKNOWN"
    assert api_findings["yara_analyzer"]["status"] == "error"
    if entity == "tool":
        api_result = _convert_scanner_result_to_tool_api_result(result, scanner)
        assert api_result.is_safe is None
        assert api_result.analyzer_errors == result.analyzer_errors


@pytest.mark.asyncio
async def test_all_analyzers_crashed_reports_failed():
    result = await _scan_entity(
        _scanner(yara_analyzer=CrashingAnalyzer()), "tool", [AnalyzerEnum.YARA]
    )

    assert result.status == "failed"
    assert result.analyzers == []
    assert result.is_safe is None
    assert filter_results_by_severity([result], "HIGH")[0].status == "failed"


@pytest.mark.asyncio
async def test_partial_analyzer_failure_retains_findings():
    class FindingThenCrash:
        async def analyze(self, content, context=None):
            if context["content_type"] == "parameters":
                raise RuntimeError("parameters failed")
            return [
                SecurityFinding(
                    severity="HIGH",
                    summary="Threat detected",
                    analyzer="YARA",
                    threat_category="TEST",
                    details={},
                )
            ]

    result = await _scan_entity(
        _scanner(yara_analyzer=FindingThenCrash()), "tool", [AnalyzerEnum.YARA]
    )
    payload = json.loads(format_results_as_json([result]))["scan_results"][0]

    assert result.status == "partial"
    assert result.is_safe is False
    assert result.analyzers == [AnalyzerEnum.YARA]
    assert len(result.findings) == 1
    assert payload["findings"]["yara_analyzer"]["severity"] == "HIGH"
    assert payload["findings"]["yara_analyzer"]["status"] == "partial"
    assert payload["status"] == "partial"

    report_rows = await results_to_json([result])
    assert report_rows[0]["findings"]["yara_analyzer"]["severity"] == "HIGH"
    assert report_rows[0]["findings"]["yara_analyzer"]["status"] == "partial"


@pytest.mark.asyncio
async def test_partial_analyzer_without_findings_stays_visible_when_filtered():
    class CleanThenCrash:
        async def analyze(self, content, context=None):
            if context["content_type"] == "parameters":
                raise RuntimeError("secret-token-must-not-leak")
            return []

    result = await _scan_entity(
        _scanner(yara_analyzer=CleanThenCrash()), "tool", [AnalyzerEnum.YARA]
    )

    assert result.status == "partial"
    assert result.analyzers == [AnalyzerEnum.YARA]
    assert result.is_safe is None
    filtered = filter_results_by_severity([result], "HIGH")
    assert len(filtered) == 1
    assert filtered[0].status == "partial"
    assert filtered[0].is_safe is None
    assert filtered[0].analyzer_errors == result.analyzer_errors


@pytest.mark.asyncio
async def test_partial_resource_with_finding_counts_as_scanned():
    class FindingAnalyzer:
        async def analyze(self, content, context=None):
            return [
                SecurityFinding(
                    severity="HIGH",
                    summary="Threat detected",
                    analyzer="API",
                    threat_category="TEST",
                    details={},
                )
            ]

    scanner = _scanner(FindingAnalyzer(), CrashingAnalyzer())
    result = await _scan_entity(
        scanner, "resource", [AnalyzerEnum.API, AnalyzerEnum.YARA]
    )

    async def scan_resources(**kwargs):
        return [result]

    scanner.scan_remote_server_resources = scan_resources
    response = await scan_all_resources_endpoint(
        APIScanRequest(
            server_url="https://example.com/mcp", analyzers=[AnalyzerEnum.YARA]
        ),
        SimpleNamespace(headers={}),
        scanner_factory=lambda _: scanner,
    )

    assert response["scanned_resources"] == 1
    assert response["partial_resources"] == 1
    assert response["failed_resources"] == 0
    assert response["unsafe_resources"] == 1
    assert response["resources"][0]["findings"]["api_analyzer"]["severity"] == "HIGH"


def test_partial_resource_table_shows_unsafe_finding(monkeypatch):
    rows = []

    def tabulate(data, **kwargs):
        rows.extend(data)
        return "table"

    monkeypatch.setitem(sys.modules, "tabulate", SimpleNamespace(tabulate=tabulate))
    display_resource_results_table(
        [
            {
                "resource_name": "example",
                "resource_uri": "file:///example.txt",
                "resource_mime_type": "text/plain",
                "status": "partial",
                "is_safe": False,
                "findings": [{"severity": "HIGH"}],
            }
        ],
        "https://example.com/mcp",
    )

    assert rows[0][0] == "⚠️"
    assert rows[0][4] == 1
    assert rows[0][5] == "partial"


@pytest.mark.asyncio
async def test_clean_scan_reports_safe_only_for_analyzers_that_ran():
    result = await _scan_entity(
        _scanner(yara_analyzer=CleanAnalyzer()), "tool", [AnalyzerEnum.YARA]
    )
    payload = json.loads(format_results_as_json([result]))["scan_results"][0]

    assert result.status == "completed"
    assert result.is_safe is True
    assert payload["findings"] == {
        "yara_analyzer": {
            "severity": "SAFE",
            "total_findings": 0,
            "threat_names": [],
            "threat_summary": "No threats detected",
        }
    }


@pytest.mark.asyncio
async def test_prompt_defense_finding_uses_single_analyzer_entry():
    finding = SecurityFinding(
        severity="HIGH",
        summary="Threat detected",
        analyzer="PromptDefense",
        threat_category="TEST",
        details={},
    )
    result = ToolScanResult(
        tool_name="example",
        tool_description="Example tool",
        status="completed",
        analyzers=[AnalyzerEnum.PROMPT_DEFENSE],
        findings=[finding],
    )

    sdk_row = json.loads(format_results_as_json([result]))["scan_results"][0]
    report_row = (await results_to_json([result]))[0]
    for row in (sdk_row, report_row):
        assert list(row["findings"]) == ["prompt_defense_analyzer"]
        assert row["findings"]["prompt_defense_analyzer"]["severity"] == "HIGH"
        assert row["findings"]["prompt_defense_analyzer"]["total_findings"] == 1


@pytest.mark.asyncio
async def test_report_summary_keeps_incomplete_scan_separate_from_unsafe():
    result = await _scan_entity(
        _scanner(CleanAnalyzer(), CrashingAnalyzer()),
        "tool",
        [AnalyzerEnum.API, AnalyzerEnum.YARA],
    )

    rows = await results_to_json([result])
    assert rows[0]["is_safe"] is None
    assert rows[0]["findings"]["api_analyzer"]["severity"] == "SAFE"
    assert rows[0]["findings"]["yara_analyzer"]["severity"] == "UNKNOWN"
    assert rows[0]["findings"]["yara_analyzer"]["status"] == "error"

    report = ReportGenerator({"server_url": "local", "scan_results": rows})
    summary = report.format_output(OutputFormat.SUMMARY)
    detailed = report.format_output(OutputFormat.DETAILED)

    assert "Unsafe items: 0" in summary
    assert "Incomplete items: 1" in summary
    assert "Safe: Unknown" in detailed
    assert "Analyzer error: YARA" in detailed
    assert report.get_statistics()["incomplete_tools"] == 1


@pytest.mark.asyncio
async def test_cli_labels_unknown_safety_as_incomplete(capsys):
    result = await _scan_entity(
        _scanner(CleanAnalyzer(), CrashingAnalyzer()),
        "tool",
        [AnalyzerEnum.API, AnalyzerEnum.YARA],
    )
    payload = json.loads(format_results_as_json([result]))

    display_results(payload, detailed=False)
    output = capsys.readouterr().out

    assert "Safe tools: 0" in output
    assert "Unsafe tools: 0" in output
    assert "Incomplete tools: 1" in output
    assert "YARA analyzer failed" in output


@pytest.mark.asyncio
async def test_meta_enrichment_preserves_primary_analyzer_errors():
    class PassingMetaAnalyzer:
        async def analyze_findings(self, findings, analyzers_used, entity_context):
            return MetaAnalysisResult()

    scanner = _scanner()
    scanner._meta_analyzer = PassingMetaAnalyzer()
    finding = SecurityFinding(
        severity="HIGH",
        summary="Threat detected",
        analyzer="YARA",
        threat_category="TEST",
        details={},
    )
    result = ToolScanResult(
        tool_name="example",
        tool_description="Example tool",
        status="partial",
        analyzers=[AnalyzerEnum.API],
        findings=[finding],
        analyzer_errors=[
            {
                "analyzer": "YARA",
                "content_type": "parameters",
                "message": "RuntimeError during analysis",
            }
        ],
    )

    enriched = await scanner._meta_analyze_one_tool(result, asyncio.Semaphore(1))

    assert enriched is not result
    assert enriched.analyzer_errors == result.analyzer_errors
    assert enriched.status == "partial"
    assert enriched.is_safe is False


@pytest.mark.asyncio
async def test_meta_analyzer_error_log_does_not_echo_provider_message():
    class CrashingMetaAnalyzer:
        async def analyze_findings(self, findings, analyzers_used, entity_context):
            raise RuntimeError("secret-token-must-not-leak")

    scanner = _scanner()
    scanner._meta_analyzer = CrashingMetaAnalyzer()
    result = ToolScanResult(
        tool_name="example",
        tool_description="Example tool",
        status="completed",
        analyzers=[AnalyzerEnum.YARA],
        findings=[
            SecurityFinding(
                severity="HIGH",
                summary="Threat detected",
                analyzer="YARA",
                threat_category="TEST",
                details={},
            )
        ],
    )

    log_output = StringIO()
    log_handler = StreamHandler(log_output)
    scanner_logger.addHandler(log_handler)
    try:
        await scanner._meta_analyze_one_tool(result, asyncio.Semaphore(1))
    finally:
        scanner_logger.removeHandler(log_handler)

    assert "secret-token-must-not-leak" not in log_output.getvalue()
    assert "RuntimeError" in log_output.getvalue()
