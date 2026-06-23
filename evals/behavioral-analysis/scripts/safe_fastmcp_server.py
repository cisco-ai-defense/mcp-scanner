# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Known-safe FastMCP server. Expected behavioral analyzer result: 0 findings."""

from fastmcp import FastMCP

mcp = FastMCP("safe-demo")


@mcp.tool()
def echo(text: str) -> str:
    """Return the provided text unchanged. No side effects, no I/O."""
    if not isinstance(text, str) or len(text) > 4096:
        raise ValueError("text must be a string up to 4096 chars")
    return text


@mcp.tool()
def add(a: float, b: float) -> float:
    """Return the sum of two finite numbers."""
    for name, v in (("a", a), ("b", b)):
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            raise TypeError(f"{name} must be a number")
        if v != v or v in (float("inf"), float("-inf")):
            raise ValueError(f"{name} must be finite")
    return float(a) + float(b)


if __name__ == "__main__":
    mcp.run()
