"""Integration tests for Python MCP framework fixture servers."""

from __future__ import annotations

from pathlib import Path

import pytest

from mcpscanner.core.analyzers.behavioral.code_analyzer import (
    BehavioralCodeAnalyzer,
    _AcceptedFile,
)
from mcpscanner.core.static_analysis.native_analyzer import NativeAnalyzer

FIXTURES_ROOT = (
    Path(__file__).resolve().parents[2]
    / "evals"
    / "research-runs"
    / "python-mcp-frameworks"
)


def _read(rel: str) -> tuple[str, str]:
    path = FIXTURES_ROOT / rel
    return path.read_text(encoding="utf-8"), str(path)


@pytest.mark.parametrize(
    ("rel_path", "expected"),
    [
        ("01_fastmcp_decorator/server.py", {"add"}),
        ("02_official_sdk_fastmcp/server.py", {"ping"}),
        ("03_programmatic_add_tool/server.py", {"multiply"}),
        ("04_mcpserver_v2/server.py", {"greet"}),
        ("05_fastapi_mcp_app/main.py", {"list_items", "create_item"}),
        ("06_fastapi_mcp_router/routes.py", {"health_check"}),
        ("07_vanilla_fastapi_mcp_mount/main.py", {"add_note"}),
        ("08_fastmcp_http_app_mount/main.py", {"greet"}),
        ("09_flask_mcp_server/app.py", {"sum_numbers"}),
        ("10_pagerduty_registration/server.py", {"list_incidents"}),
        ("12_hand_rolled_flask/app.py", {"add", "search"}),
        ("13_hand_rolled_fastapi/main.py", {"add", "list_items"}),
        ("14_hand_rolled_fastapi_router/routes.py", {"echo"}),
        ("15_hand_rolled_register/app.py", {"multiply"}),
    ],
)
def test_python_framework_fixture_extracts_tools(rel_path: str, expected: set[str]) -> None:
    source, file_path = _read(rel_path)
    caps = NativeAnalyzer(source, file_path).extract_mcp_capability_contexts()
    assert {c.name for c in caps} == expected


@pytest.mark.parametrize(
    "rel_path",
    [
        "negative/flask_rest_only/app.py",
        "negative/fastapi_rest_only/main.py",
    ],
)
def test_python_framework_negative_rest_has_no_tools(rel_path: str) -> None:
    source, file_path = _read(rel_path)
    analyzer = NativeAnalyzer(source, file_path)
    assert not analyzer._has_mcp_markers()
    assert analyzer.extract_mcp_capability_contexts() == []


def test_python_framework_negative_lambda_dispatch_gap() -> None:
    source, file_path = _read("negative/lambda_dispatch/main.py")
    analyzer = NativeAnalyzer(source, file_path)
    assert analyzer._has_mcp_markers()
    assert analyzer.extract_mcp_capability_contexts() == []


@pytest.mark.parametrize(
    ("rel_path", "tool_name"),
    [
        ("11_pagerduty_tool_module/demo_mcp/tools/incidents.py", "list_incidents"),
        ("11_pagerduty_tool_module/demo_mcp/tools/alerts.py", "list_alerts"),
    ],
)
def test_python_framework_tool_handler_modules(rel_path: str, tool_name: str) -> None:
    source, file_path = _read(rel_path)
    analyzer = NativeAnalyzer(source, file_path)
    assert not analyzer._has_mcp_markers()
    caps = analyzer.extract_mcp_capability_contexts(tool_handler_module=True)
    assert len(caps) == 1
    assert caps[0].name == tool_name
    assert "<tool_module>.tool" in caps[0].decorator_types


def test_python_framework_pagerduty_tools_dir_expansion() -> None:
    root = FIXTURES_ROOT / "11_pagerduty_tool_module"
    server_py = root / "demo_mcp" / "server.py"
    incidents = root / "demo_mcp" / "tools" / "incidents.py"
    alerts = root / "demo_mcp" / "tools" / "alerts.py"

    analyzer = BehavioralCodeAnalyzer.__new__(BehavioralCodeAnalyzer)
    accepted = [
        _AcceptedFile(
            path=str(server_py),
            source_bytes=server_py.read_bytes(),
            source_text=server_py.read_text(encoding="utf-8"),
        )
    ]
    expanded = analyzer._expand_tool_handler_modules(
        accepted,
        [str(server_py), str(incidents), str(alerts)],
    )
    handler_paths = {item.path for item in expanded if item.tool_handler_module}
    assert str(incidents) in handler_paths
    assert str(alerts) in handler_paths


def test_fastapi_mcp_route_tools_tagged() -> None:
    source, file_path = _read("05_fastapi_mcp_app/main.py")
    caps = NativeAnalyzer(source, file_path).extract_mcp_capability_contexts()
    assert all(any("fastapi_mcp" in t for t in c.decorator_types) for c in caps)


def test_hand_rolled_flask_tools_tagged() -> None:
    source, file_path = _read("12_hand_rolled_flask/app.py")
    caps = NativeAnalyzer(source, file_path).extract_mcp_capability_contexts()
    assert all(any("hand_rolled_mcp" in t for t in c.decorator_types) for c in caps)


def test_vanilla_fastapi_mount_web_transport_tag() -> None:
    source, file_path = _read("07_vanilla_fastapi_mcp_mount/main.py")
    caps = NativeAnalyzer(source, file_path).extract_mcp_capability_contexts()
    assert any("web_transport" in t for c in caps for t in c.decorator_types)


def test_programmatic_add_tool_registration_tag() -> None:
    source, file_path = _read("03_programmatic_add_tool/server.py")
    caps = NativeAnalyzer(source, file_path).extract_mcp_capability_contexts()
    assert caps[0].name == "multiply"
    assert "<registration>.tool" in caps[0].decorator_types
