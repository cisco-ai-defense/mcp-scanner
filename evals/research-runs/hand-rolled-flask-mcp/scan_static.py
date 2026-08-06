#!/usr/bin/env python3
"""Static MCP capability scan for the hand-rolled Flask demo."""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from mcpscanner.core.static_analysis.native_analyzer import NativeAnalyzer  # noqa: E402


def scan_tree(root: Path) -> None:
    py_files = sorted(root.rglob("*.py"))
    py_files = [p for p in py_files if "__pycache__" not in p.parts]

    print(f"Scanning {len(py_files)} Python file(s) under {root}\n")

    all_tools: dict[str, list[str]] = {}
    for path in py_files:
        source = path.read_text(encoding="utf-8")
        rel = path.relative_to(root.parent)
        analyzer = NativeAnalyzer(source, str(path))
        caps = analyzer.extract_mcp_capability_contexts()
        names = [c.name for c in caps]
        tags = sorted({t for c in caps for t in c.decorator_types})
        all_tools[str(rel)] = names
        status = f"{len(names)} tool(s)" if names else "no tools"
        print(f"  {rel}: {status}")
        if names:
            for c in caps:
                dec = ", ".join(c.decorator_types) or "-"
                print(f"    - {c.name!r}  [{dec}]")
        elif analyzer._has_mcp_markers():
            print("    (MCP markers present, no extractable tools)")

    print("\n--- Behavioral prefilter (files kept for scan) ---")
    for path in py_files:
        rel = path.relative_to(root.parent)
        source = path.read_text(encoding="utf-8")
        if NativeAnalyzer(source, str(path))._has_mcp_markers():
            print(f"  KEEP {rel}")

    registry_tools = sorted(
        name for file, names in all_tools.items() if "server/" in file for name in names
    )
    switch_tools = sorted(all_tools.get("switch_dispatch.py", []))

    print("\n--- Summary ---")
    print(f"Registry server tools: {registry_tools or '(none)'}")
    print(f"Switch-dispatch tools: {switch_tools or '(none — expected gap)'}")
    expected = {"add", "search", "status"}
    found = set(registry_tools)
    if found == expected:
        print("Registry pattern: PASS")
    else:
        print(f"Registry pattern: FAIL (expected {sorted(expected)}, got {sorted(found)})")
        sys.exit(1)


if __name__ == "__main__":
    demo_root = Path(__file__).resolve().parent
    scan_tree(demo_root)
