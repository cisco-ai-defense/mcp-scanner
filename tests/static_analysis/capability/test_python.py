# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Per-language capability tests for Python.

Python detection runs through the standard library's ``ast`` module
rather than tree-sitter; the adapter at
:mod:`mcpscanner.core.static_analysis.capability.python` returns
``None`` from ``tree_sitter_language()`` and overrides
``extract_with_native_parser`` to delegate to the dedicated
``_py_extract_capability_contexts`` pipeline.

Fixtures track FastMCP and the official Python MCP SDK low-level
``Server`` shape; both are exercised here.
"""

from __future__ import annotations

from .conftest import (
    assert_helpers_only,
    assert_mixed_yields,
    names_of,
)
from mcpscanner.core.static_analysis import NativeAnalyzer


HELPERS_ONLY = '''
def _internal_normalize(s: str) -> str:
    return s.strip().lower()

def _validate_number(name, v):
    if not isinstance(v, (int, float)):
        raise TypeError(name)

def util_format(label, value):
    return f"{label}={value}"
'''

MIXED = '''
from fastmcp import FastMCP

mcp = FastMCP("plus-helpers")

def _validate(name, v):
    pass

def _coerce(v):
    return float(v)

@mcp.tool()
def add(a: float, b: float) -> float:
    """Return the sum of two numbers."""
    _validate("a", a); _validate("b", b)
    return _coerce(a) + _coerce(b)
'''


LOWLEVEL_SERVER = '''
from mcp.server import Server

server = Server("demo")

def helper(x):
    return x

@server.call_tool()
async def call_tool(name, arguments):
    """Dispatch a tool call."""
    return helper(arguments)

@server.list_tools()
async def list_tools():
    """Enumerate tools."""
    return []
'''


def test_helpers_only_yields_no_capabilities() -> None:
    assert_helpers_only(HELPERS_ONLY, "helpers.py")


def test_mixed_file_returns_only_capabilities() -> None:
    assert_mixed_yields(MIXED, "mixed.py", {"add"})


def test_decorator_metadata_is_preserved() -> None:
    """Python capabilities retain the original decorator string so
    callers can tell which kind of MCP primitive they correspond to."""
    analyzer = NativeAnalyzer(MIXED, "mixed.py")
    caps = analyzer.extract_mcp_capability_contexts()
    assert len(caps) == 1
    assert any(
        d.endswith("tool") or d.endswith("tool()")
        for d in caps[0].decorator_types
    ), caps[0].decorator_types


def test_lowlevel_server_decorators_classify_as_capabilities() -> None:
    """Python low-level Server's ``@server.call_tool`` and
    ``@server.list_tools`` must classify as MCP tools (Gap 1)."""
    analyzer = NativeAnalyzer(LOWLEVEL_SERVER, "lowlevel.py")
    caps = analyzer.extract_mcp_capability_contexts()
    names = names_of(caps)
    assert "call_tool" in names, names
    assert "list_tools" in names, names
    assert "helper" not in names, names


def test_extract_all_function_contexts_unchanged() -> None:
    """``extract_all_function_contexts`` must keep returning every
    function regardless of MCP decoration; capability filtering is
    opt-in via the new method."""
    analyzer = NativeAnalyzer(MIXED, "mixed.py")
    full = analyzer.extract_all_function_contexts()
    names = {fn.name for fn in full}
    assert {"_validate", "_coerce", "add"}.issubset(names), names
