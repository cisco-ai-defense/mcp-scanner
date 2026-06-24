# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Fixture: Python file with NO @mcp.* decorators, only plain helper
functions. Used to reproduce a CLI/SDK bug where the behavioral analyzer
treats every plain Python function as if it were an MCP tool, instead of
returning an empty inventory (or just the actually-decorated capabilities).

Expected behavior after fix: zero tool rows surface; CLI emits the
"No MCP capabilities detected" fallback row.
"""


def _internal_normalize(s: str) -> str:
    return s.strip().lower()


def _validate_number(name: str, v) -> None:
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        raise TypeError(f"{name} must be a number")


def util_format(label: str, value) -> str:
    return f"{label}={value}"
