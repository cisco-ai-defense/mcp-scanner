#!/usr/bin/env python3
"""Scan all Python MCP framework fixtures and verify expected tool extraction."""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import FrozenSet, Optional, Set

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from mcpscanner.core.analyzers.behavioral.code_analyzer import (  # noqa: E402
    BehavioralCodeAnalyzer,
    _AcceptedFile,
)
from mcpscanner.core.static_analysis.native_analyzer import NativeAnalyzer  # noqa: E402

FIXTURES_ROOT = Path(__file__).resolve().parent


@dataclass(frozen=True)
class FrameworkCase:
    name: str
    rel_path: str
    expected_tools: FrozenSet[str]
    tool_handler_module: bool = False
    expect_mcp_markers: bool = True


CASES: tuple[FrameworkCase, ...] = (
    FrameworkCase("fastmcp_decorator", "01_fastmcp_decorator/server.py", frozenset({"add"})),
    FrameworkCase("official_sdk_fastmcp", "02_official_sdk_fastmcp/server.py", frozenset({"ping"})),
    FrameworkCase("programmatic_add_tool", "03_programmatic_add_tool/server.py", frozenset({"multiply"})),
    FrameworkCase("mcpserver_v2", "04_mcpserver_v2/server.py", frozenset({"greet"})),
    FrameworkCase(
        "fastapi_mcp_app",
        "05_fastapi_mcp_app/main.py",
        frozenset({"list_items", "create_item"}),
    ),
    FrameworkCase(
        "fastapi_mcp_router",
        "06_fastapi_mcp_router/routes.py",
        frozenset({"health_check"}),
    ),
    FrameworkCase(
        "vanilla_fastapi_mcp_mount",
        "07_vanilla_fastapi_mcp_mount/main.py",
        frozenset({"add_note"}),
    ),
    FrameworkCase(
        "fastmcp_http_app_mount",
        "08_fastmcp_http_app_mount/main.py",
        frozenset({"greet"}),
    ),
    FrameworkCase(
        "flask_mcp_server",
        "09_flask_mcp_server/app.py",
        frozenset({"sum_numbers"}),
    ),
    FrameworkCase(
        "pagerduty_registration",
        "10_pagerduty_registration/server.py",
        frozenset({"list_incidents"}),
    ),
    FrameworkCase(
        "pagerduty_tool_module_incidents",
        "11_pagerduty_tool_module/demo_mcp/tools/incidents.py",
        frozenset({"list_incidents"}),
        tool_handler_module=True,
        expect_mcp_markers=False,
    ),
    FrameworkCase(
        "pagerduty_tool_module_alerts",
        "11_pagerduty_tool_module/demo_mcp/tools/alerts.py",
        frozenset({"list_alerts"}),
        tool_handler_module=True,
        expect_mcp_markers=False,
    ),
    FrameworkCase(
        "hand_rolled_flask",
        "12_hand_rolled_flask/app.py",
        frozenset({"add", "search"}),
    ),
    FrameworkCase(
        "hand_rolled_fastapi",
        "13_hand_rolled_fastapi/main.py",
        frozenset({"add", "list_items"}),
    ),
    FrameworkCase(
        "hand_rolled_fastapi_router",
        "14_hand_rolled_fastapi_router/routes.py",
        frozenset({"echo"}),
    ),
    FrameworkCase(
        "hand_rolled_register",
        "15_hand_rolled_register/app.py",
        frozenset({"multiply"}),
    ),
    FrameworkCase(
        "negative_flask_rest",
        "negative/flask_rest_only/app.py",
        frozenset(),
        expect_mcp_markers=False,
    ),
    FrameworkCase(
        "negative_fastapi_rest",
        "negative/fastapi_rest_only/main.py",
        frozenset(),
        expect_mcp_markers=False,
    ),
    FrameworkCase(
        "negative_lambda_dispatch",
        "negative/lambda_dispatch/main.py",
        frozenset(),
    ),
)


def extract_tools(path: Path, *, tool_handler_module: bool = False) -> Set[str]:
    source = path.read_text(encoding="utf-8")
    analyzer = NativeAnalyzer(source, str(path))
    caps = analyzer.extract_mcp_capability_contexts(
        tool_handler_module=tool_handler_module
    )
    return {c.name for c in caps}


def test_pagerduty_expansion() -> None:
    """Behavioral prefilter expands sibling tools/ modules."""
    root = FIXTURES_ROOT / "11_pagerduty_tool_module"
    server_py = root / "demo_mcp" / "server.py"
    incidents = root / "demo_mcp" / "tools" / "incidents.py"
    alerts = root / "demo_mcp" / "tools" / "alerts.py"
    source_files = [str(server_py), str(incidents), str(alerts)]

    analyzer = BehavioralCodeAnalyzer.__new__(BehavioralCodeAnalyzer)
    accepted = [
        _AcceptedFile(
            path=str(server_py),
            source_bytes=server_py.read_bytes(),
            source_text=server_py.read_text(encoding="utf-8"),
        )
    ]
    expanded = analyzer._expand_tool_handler_modules(accepted, source_files)
    handler_paths = {item.path for item in expanded if item.tool_handler_module}
    assert str(incidents) in handler_paths
    assert str(alerts) in handler_paths


def main() -> int:
    passed = 0
    failed = 0

    print(f"Scanning {len(CASES)} Python MCP framework fixture(s)\n")

    for case in CASES:
        path = FIXTURES_ROOT / case.rel_path
        if not path.is_file():
            print(f"  FAIL {case.name}: missing {case.rel_path}")
            failed += 1
            continue

        source = path.read_text(encoding="utf-8")
        analyzer = NativeAnalyzer(source, str(path))
        has_markers = analyzer._has_mcp_markers()
        if has_markers != case.expect_mcp_markers:
            print(
                f"  FAIL {case.name}: markers expected={case.expect_mcp_markers} "
                f"got={has_markers}"
            )
            failed += 1
            continue

        found = extract_tools(path, tool_handler_module=case.tool_handler_module)
        if found == set(case.expected_tools):
            print(f"  PASS {case.name}: {sorted(found) or '(none)'}")
            passed += 1
        else:
            print(
                f"  FAIL {case.name}: expected {sorted(case.expected_tools)} "
                f"got {sorted(found)}"
            )
            failed += 1

    print("\n--- Expansion ---")
    try:
        test_pagerduty_expansion()
        print("  PASS pagerduty_tool_module_expansion")
        passed += 1
    except AssertionError as exc:
        print(f"  FAIL pagerduty_tool_module_expansion: {exc}")
        failed += 1

    print(f"\n--- Summary: {passed} passed, {failed} failed ---")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
