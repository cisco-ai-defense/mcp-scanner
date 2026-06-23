# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Per-language capability tests for Java (Spring AI / official MCP SDK).

Java detection is annotation-driven: handlers are annotated with
``@Tool`` / ``@McpTool`` / ``@McpResource`` / ``@McpPrompt``. Bare
``@Tool`` only classifies as MCP when the file imports from one of the
trusted namespaces (``org.springframework.ai`` or
``io.modelcontextprotocol``).
"""

from __future__ import annotations

from .conftest import (
    assert_helpers_only,
    assert_mixed_yields,
    assert_source_kind_tag,
    names_of,
)
from mcpscanner.core.static_analysis import NativeAnalyzer


HELPERS_ONLY = """\
package demo;

public class Helpers {
    public double normalize(double x) { return x; }
    public double helper(double a, double b) { return a + b; }
}
"""

MIXED = """\
package demo;

import org.springframework.ai.tool.annotation.Tool;
import org.springframework.stereotype.Service;

@Service
public class CalcService {

    private double normalize(double x) { return x; }

    @Tool(description = "Add two numbers")
    public double add(double a, double b) {
        return normalize(a) + normalize(b);
    }
}
"""


ANNOTATION_INDEX_FIXTURE = """\
package demo;
import org.springframework.ai.mcp.Tool;

public class Calc {
    private double helper(double x) { return x; }
    @Tool(description = "Add")
    public double add(double a, double b) { return a + b; }
}
"""


def test_helpers_only_yields_no_capabilities() -> None:
    assert_helpers_only(HELPERS_ONLY, "Helpers.java")


def test_mixed_file_returns_only_capabilities() -> None:
    assert_mixed_yields(MIXED, "Mixed.java", {"CalcService.add"})


def test_source_kind_tag_is_annotation() -> None:
    assert_source_kind_tag(MIXED, "Mixed.java", "<annotation>.tool")


def test_annotation_index_collects_decorators_once() -> None:
    """The annotation index must populate even for a single annotated
    function in a haystack (Gap 13)."""
    analyzer = NativeAnalyzer(ANNOTATION_INDEX_FIXTURE, "Calc.java")
    caps = analyzer.extract_mcp_capability_contexts()
    assert names_of(caps) == {"Calc.add"}, names_of(caps)
    cache = getattr(analyzer, "_annotation_index_cache", None)
    assert cache is not None and any(cache.values()), cache
