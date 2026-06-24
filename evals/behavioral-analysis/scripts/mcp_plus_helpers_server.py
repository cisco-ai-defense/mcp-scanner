# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Fixture: Python file with 1 @mcp.tool() capability + 2 plain helper
functions. The behavioral CLI must surface exactly 1 row (the decorated
``add``), NOT 3 (decorated + both helpers)."""

from fastmcp import FastMCP


mcp = FastMCP("plus-helpers-demo")


def _validate_number(name: str, v) -> None:
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        raise TypeError(f"{name} must be a number")


def _coerce(v) -> float:
    return float(v)


@mcp.tool()
def add(a: float, b: float) -> float:
    """Return the sum of two finite numbers."""
    _validate_number("a", a)
    _validate_number("b", b)
    return _coerce(a) + _coerce(b)


if __name__ == "__main__":
    mcp.run()
