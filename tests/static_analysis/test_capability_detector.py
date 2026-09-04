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

"""Unit tests for ``CapabilityDetector`` and ``CapabilityRecord``.

These tests exercise the new public API in
:mod:`mcpscanner.core.static_analysis.capability_detector` directly,
without going through the deprecation shim on ``NativeAnalyzer``.

The legacy shim is also covered (deprecation warning, identical
output) so the refactor stays backward compatible.
"""

from __future__ import annotations

import warnings

import pytest

from mcpscanner.core.static_analysis import (
    CapabilityDetector,
    CapabilityRecord,
    NativeAnalyzer,
)


# ---------------------------------------------------------------------------
# Sample fixtures
# ---------------------------------------------------------------------------

PYTHON_FASTMCP_TOOL = """\
from mcp.server import Server

mcp = Server()


@mcp.tool()
def add(a: int, b: int) -> int:
    \"\"\"Sum two numbers.\"\"\"
    return a + b


@mcp.prompt()
def greet(name: str) -> str:
    return f"Hello, {name}!"


@mcp.resource("docs://readme")
def readme() -> str:
    return "Project README contents."


def helper(x):
    \"\"\"Plain helper — must NOT be returned as a capability.\"\"\"
    return x * 2
"""


TS_REGISTRATION = """\
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

const server = new McpServer({ name: "demo", version: "1.0.0" });

function add(a, b) {
    return a + b;
}

server.tool("add", { description: "Sum" }, add);
"""


JAVA_SPRING_AI_TOOL = """\
package demo;

import org.springframework.ai.mcp.Tool;

public class Calc {
    private double helper(double x) { return x; }

    @Tool(description = "Add two numbers")
    public double add(double a, double b) {
        return a + b;
    }
}
"""


# ---------------------------------------------------------------------------
# detect() — primary CapabilityRecord-shaped entry point
# ---------------------------------------------------------------------------


def test_detect_returns_capability_records_for_python_fastmcp() -> None:
    """``detect()`` surfaces tool / prompt / resource — and skips helpers."""
    analyzer = NativeAnalyzer(PYTHON_FASTMCP_TOOL, "demo.py")
    detector = CapabilityDetector(analyzer)

    records = detector.detect()

    assert all(isinstance(r, CapabilityRecord) for r in records), records
    capabilities = sorted(r.capability for r in records)
    assert capabilities == ["prompt", "resource", "tool"], capabilities

    names = sorted(r.name for r in records if r.name)
    assert names == ["add", "greet", "readme"], names

    # ``helper`` is a plain function, not an MCP capability.
    assert "helper" not in {r.name for r in records}


def test_detect_returns_capability_records_for_ts_registration() -> None:
    """``server.tool('add', ..., handler)`` resolves to a tool record."""
    analyzer = NativeAnalyzer(TS_REGISTRATION, "demo.ts")
    detector = CapabilityDetector(analyzer)

    records = detector.detect()

    assert len(records) == 1
    rec = records[0]
    assert rec.capability == "tool"
    assert rec.name in {"add", "add (add)"}
    assert rec.source_kind.startswith("registration")


def test_detect_returns_capability_records_for_java_spring_ai() -> None:
    """``@Tool``-annotated methods classify as tools."""
    analyzer = NativeAnalyzer(JAVA_SPRING_AI_TOOL, "Calc.java")
    detector = CapabilityDetector(analyzer)

    records = detector.detect()

    assert len(records) == 1
    rec = records[0]
    assert rec.capability == "tool"
    assert rec.name == "Calc.add"
    assert rec.source_kind == "annotation"


def test_detect_records_carry_function_context_payload() -> None:
    """Each record exposes the underlying ``FunctionContext`` for callers
    that still need code-shape details (decorators, docstring, ...)."""
    analyzer = NativeAnalyzer(PYTHON_FASTMCP_TOOL, "demo.py")
    detector = CapabilityDetector(analyzer)

    records = detector.detect()

    contexts = [r.function_context for r in records]
    assert all(ctx is not None for ctx in contexts)
    docs = {ctx.name: getattr(ctx, "docstring", None) for ctx in contexts if ctx}
    assert "add" in docs


# ---------------------------------------------------------------------------
# extract_mcp_capability_contexts() — backward-compat FunctionContext path
# ---------------------------------------------------------------------------


def test_legacy_function_context_path_yields_same_capabilities() -> None:
    """``CapabilityDetector.extract_mcp_capability_contexts`` and
    ``detect`` must agree on which capabilities are detected."""
    analyzer = NativeAnalyzer(PYTHON_FASTMCP_TOOL, "demo.py")
    detector = CapabilityDetector(analyzer)

    legacy = detector.extract_mcp_capability_contexts()
    records = detector.detect()

    assert len(legacy) == len(records)
    assert {ctx.name for ctx in legacy} == {r.name for r in records}


def test_legacy_function_context_includes_decorator_tags() -> None:
    """The legacy entry point must keep emitting decorator tags so existing
    consumers (alignment LLM, reports) keep working unchanged."""
    analyzer = NativeAnalyzer(PYTHON_FASTMCP_TOOL, "demo.py")
    detector = CapabilityDetector(analyzer)

    contexts = detector.extract_mcp_capability_contexts()
    add_ctx = next(c for c in contexts if c.name == "add")

    # FastMCP-style: ``mcp.tool`` is the captured decorator name.
    assert any(
        dec.endswith("tool") or dec.endswith(".tool")
        for dec in (add_ctx.decorator_types or [])
    ), add_ctx.decorator_types


# ---------------------------------------------------------------------------
# Composition with NativeAnalyzer + delegation
# ---------------------------------------------------------------------------


def test_detector_delegates_unknown_attrs_to_analyzer() -> None:
    """The detector must transparently expose analyzer state (language,
    source bytes, helper methods) so the migrated logic keeps working
    without renames."""
    analyzer = NativeAnalyzer(PYTHON_FASTMCP_TOOL, "demo.py")
    detector = CapabilityDetector(analyzer)

    assert detector.language == "python"
    assert detector.source_code == PYTHON_FASTMCP_TOOL
    # Helper methods declared on NativeAnalyzer must still be reachable
    # via the detector — the migrated capability code calls
    # ``self._py_extract_function``, ``self._ts_get_node_text``, etc.
    assert callable(detector._py_extract_function)


def test_detector_specific_methods_shadow_analyzer() -> None:
    """The migrated methods live on ``CapabilityDetector``; ``__getattr__``
    must NOT re-route them through the analyzer (which no longer
    defines them)."""
    analyzer = NativeAnalyzer(PYTHON_FASTMCP_TOOL, "demo.py")
    detector = CapabilityDetector(analyzer)

    # ``_resolve_cross_file_handler`` is migrated — must be on the
    # detector, not the analyzer.
    assert "_resolve_cross_file_handler" in vars(CapabilityDetector)
    assert not hasattr(NativeAnalyzer, "_resolve_cross_file_handler")


# ---------------------------------------------------------------------------
# Backward-compat shim on NativeAnalyzer
# ---------------------------------------------------------------------------


def test_native_analyzer_shim_emits_deprecation_warning() -> None:
    """``NativeAnalyzer.extract_mcp_capability_contexts`` is now a thin
    forwarding shim and must surface a ``DeprecationWarning`` so
    integrators can plan their migration."""
    analyzer = NativeAnalyzer(PYTHON_FASTMCP_TOOL, "demo.py")

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        analyzer.extract_mcp_capability_contexts()

    deprecations = [w for w in caught if issubclass(w.category, DeprecationWarning)]
    assert len(deprecations) == 1
    assert "CapabilityDetector" in str(deprecations[0].message)


def test_native_analyzer_shim_returns_same_output_as_detector() -> None:
    """The shim and the detector entry point must agree by-name."""
    analyzer = NativeAnalyzer(PYTHON_FASTMCP_TOOL, "demo.py")

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        legacy = analyzer.extract_mcp_capability_contexts()

    detector = CapabilityDetector(NativeAnalyzer(PYTHON_FASTMCP_TOOL, "demo.py"))
    direct = detector.extract_mcp_capability_contexts()

    assert {c.name for c in legacy} == {c.name for c in direct}


# ---------------------------------------------------------------------------
# Backward-compat re-exports
# ---------------------------------------------------------------------------


def test_native_analyzer_reexports_classifier_constants() -> None:
    """Tests / integrations that imported MCP-specific symbols from
    ``native_analyzer`` directly must keep working — the module
    re-exports them after the refactor."""
    from mcpscanner.core.static_analysis import native_analyzer as na

    assert na._MCP_ANNOTATION_RE is not None
    assert na._MCP_PREFILTER_RE is not None
    assert na._classify_mcp_annotation([" @Tool"], language="java") == "tool"
    # Identity check: the re-export must point at the canonical object
    # in ``capability_detector`` rather than a copy.
    from mcpscanner.core.static_analysis import capability_detector as cd

    assert na._MCP_ANNOTATION_RE is cd._MCP_ANNOTATION_RE


def test_static_analysis_package_exports_new_public_api() -> None:
    """The package-level ``__init__`` advertises the new entry points."""
    from mcpscanner.core import static_analysis

    assert "CapabilityDetector" in static_analysis.__all__
    assert "CapabilityRecord" in static_analysis.__all__
    assert hasattr(static_analysis, "CapabilityDetector")
    assert hasattr(static_analysis, "CapabilityRecord")


# ---------------------------------------------------------------------------
# Empty / no-op behavior
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("ext", [".py", ".ts", ".java", ".rs", ".rb"])
def test_detect_returns_empty_for_no_marker_files(ext: str) -> None:
    """Files with zero MCP marker tokens must classify as no-capabilities."""
    src = "x = 1\ndef f():\n    return x\n"
    analyzer = NativeAnalyzer(src, f"plain{ext}")
    detector = CapabilityDetector(analyzer)

    assert detector.detect() == []
    assert detector.extract_mcp_capability_contexts() == []
