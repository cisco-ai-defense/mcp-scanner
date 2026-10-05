"""Regression tests for scan-time tool schema reference inspection."""

import json
import sys

import pytest
from mcp.types import Tool

from mcpscanner import Config, Scanner
from mcpscanner.api.router import _group_findings_for_api
from mcpscanner.core.analyzers.schema_reference_analyzer import (
    SchemaReferenceAnalyzer,
)
from mcpscanner.core.analyzers.static_analyzer import StaticAnalyzer
from mcpscanner.core.models import AnalyzerEnum
from mcpscanner.cli import main as cli_main


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("ref", "classification", "severity"),
    [
        ("#/$defs/User", None, None),
        ("schemas/user.json", None, None),
        ("https://example.org/schema.json", "external-network", "MEDIUM"),
        ("http://127.0.0.1:8080/schema", "private-network", "HIGH"),
        ("http://[::1]/schema", "private-network", "HIGH"),
        ("http://169.254.169.254/latest/meta-data", "private-network", "HIGH"),
        ("file:///etc/passwd", "local-file", "HIGH"),
    ],
)
async def test_classifies_schema_references(ref, classification, severity):
    analyzer = SchemaReferenceAnalyzer()
    content = json.dumps(
        {
            "name": "lookup",
            "inputSchema": {"$defs": {"User": {"type": "object"}}},
            "outputSchema": {"properties": {"result": {"$ref": ref}}},
        }
    )
    findings = await analyzer.analyze(content)
    if classification is None:
        assert findings == []
    else:
        assert len(findings) == 1
        assert findings[0].severity == severity
        assert findings[0].details["classification"] == classification
        assert findings[0].details["schema_path"].startswith("outputSchema")
        assert findings[0].details["check_id"] == "MCPS-011"


@pytest.mark.asyncio
async def test_schema_scan_has_bounded_findings():
    analyzer = SchemaReferenceAnalyzer()
    content = json.dumps(
        {
            "inputSchema": {
                "anyOf": [{"$ref": "https://example.org/a"} for _ in range(100)]
            }
        }
    )
    assert len(await analyzer.analyze(content)) == analyzer.MAX_REFS


@pytest.mark.asyncio
async def test_relative_reference_is_classified_but_keeps_tool_safe(tmp_path):
    analyzer = SchemaReferenceAnalyzer()
    assert analyzer._classify_ref("schemas/user.json") == ("INFO", "relative")
    tool = Tool(
        name="lookup",
        description="Lookup a record",
        inputSchema={"$ref": "schemas/user.json"},
    )
    result = await Scanner(Config(api_key="test_api_key"))._analyze_tool(
        tool, [AnalyzerEnum.SCHEMA]
    )
    assert result.is_safe
    file_path = tmp_path / "tools.json"
    file_path.write_text(
        json.dumps(
            {
                "tools": [
                    {"name": "lookup", "inputSchema": {"$ref": "schemas/user.json"}}
                ]
            }
        ),
        encoding="utf-8",
    )
    static_results = await StaticAnalyzer([analyzer]).scan_tools_file(file_path)
    assert static_results[0]["is_safe"]


@pytest.mark.asyncio
async def test_scanner_tool_path_includes_schema_findings():
    scanner = Scanner(Config(api_key="test_api_key"))
    tool = Tool(
        name="lookup",
        description="Lookup a record",
        inputSchema={
            "type": "object",
            "properties": {"x": {"$ref": "http://localhost/schema"}},
        },
    )
    result = await scanner._analyze_tool(tool, [AnalyzerEnum.SCHEMA])
    assert len(result.findings) == 1
    assert result.findings[0].analyzer == "SCHEMA"
    assert result.findings[0].details["classification"] == "private-network"
    grouped = _group_findings_for_api(result, scanner)
    assert grouped["schema_analyzer"]["total_findings"] == 1


@pytest.mark.asyncio
async def test_static_tool_path_checks_output_schema_only(tmp_path):
    file_path = tmp_path / "tools.json"
    file_path.write_text(
        json.dumps(
            {
                "tools": [
                    {
                        "name": "lookup",
                        "description": "Lookup a record",
                        "outputSchema": {"$ref": "https://example.org/schema.json"},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    results = await StaticAnalyzer([SchemaReferenceAnalyzer()]).scan_tools_file(
        file_path
    )
    assert len(results) == 1
    assert len(results[0]["findings"]) == 1
    assert results[0]["findings"][0].details["classification"] == "external-network"


@pytest.mark.asyncio
async def test_output_only_schema_does_not_expand_other_static_analyzers(tmp_path):
    class RecordingAnalyzer:
        name = "YARA"

        def __init__(self):
            self.seen = []

        async def analyze(self, content, context=None):
            self.seen.append(context["content_type"])
            return []

    file_path = tmp_path / "tools.json"
    file_path.write_text(
        json.dumps(
            {
                "tools": [
                    {
                        "name": "lookup",
                        "description": "Lookup a record",
                        "outputSchema": {"$ref": "https://example.org/schema"},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    yara = RecordingAnalyzer()
    results = await StaticAnalyzer([yara, SchemaReferenceAnalyzer()]).scan_tools_file(
        file_path
    )
    assert yara.seen == ["description"]
    assert len(results[0]["findings"]) == 1
    assert results[0]["findings"][0].analyzer == "SCHEMA"


@pytest.mark.asyncio
async def test_static_cli_schema_only(tmp_path, monkeypatch, capsys):
    file_path = tmp_path / "tools.json"
    file_path.write_text(
        json.dumps(
            {
                "tools": [
                    {"name": "lookup", "outputSchema": {"$ref": "file:///etc/passwd"}}
                ]
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "mcp-scanner",
            "--analyzers",
            "schema",
            "--raw",
            "static",
            "--tools",
            str(file_path),
        ],
    )
    await cli_main()
    results = json.loads(capsys.readouterr().out)
    assert results[0]["findings"]["schema_analyzer"]["total_findings"] == 1
