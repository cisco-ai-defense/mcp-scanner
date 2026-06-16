# Copyright 2026 Cisco Systems, Inc. and its affiliates
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

"""Performance regression guards for ``extract_mcp_capability_contexts``.

These tests are loose budgets — they exist to catch the failure mode
where a refactor accidentally reintroduces the per-helper dataflow
analysis that PR #177 was meant to eliminate (Gap 5) or quadratic
symbol resolution from Gap 6.

The budgets are deliberately generous (well above measured times on
modest hardware) to avoid false positives in CI environments. If a
budget trips, investigate before relaxing it.
"""

import time

import pytest

from mcpscanner.core.static_analysis import NativeAnalyzer


# 1000 helper-only functions. With the prefilter, this should
# short-circuit before tree-sitter / ast.parse runs.
LARGE_HELPERS_ONLY_PYTHON = "\n".join(
    f"def helper_{i}(x):\n    return x + {i}\n" for i in range(1000)
)


# 1 decorated tool + 200 helpers. The capability path must NOT pay full
# dataflow cost on the helpers; only ``add`` should run through
# ``ForwardDataflowAnalysis``.
PYTHON_TOOL_PLUS_HELPERS = "\n".join(
    [
        "from fastmcp import FastMCP",
        'mcp = FastMCP("demo")',
        *[f"def _helper_{i}(x):\n    return x + {i}\n" for i in range(200)],
        "@mcp.tool()",
        "def add(a: int, b: int) -> int:",
        "    return a + b",
    ]
)


def test_prefilter_zero_marker_file_is_fast() -> None:
    """1000-line helper-only file must extract in well under 50 ms.

    With the byte-level prefilter (Gap 12) the file should not be
    parsed by tree-sitter or by ``ast.parse`` at all — the prefilter
    short-circuits to ``[]`` after one regex pass.
    """
    analyzer = NativeAnalyzer(LARGE_HELPERS_ONLY_PYTHON, "huge.py")
    t0 = time.perf_counter()
    caps = analyzer.extract_mcp_capability_contexts()
    elapsed = (time.perf_counter() - t0) * 1000
    assert caps == []
    # Prefilter is a single regex pass over ~25 kB; on any reasonable
    # box this is well under 50 ms. If this trips, the prefilter has
    # likely been bypassed or its regex made significantly more
    # expensive.
    assert elapsed < 50, f"prefilter too slow: {elapsed:.1f} ms"


def test_python_capability_path_skips_helper_dataflow() -> None:
    """1 decorated tool + 200 helpers must extract in well under 500 ms.

    If this trips, ``_py_extract_capability_contexts`` is likely
    falling back to the legacy ``extract_all_function_contexts`` path
    that pays full dataflow cost on every helper.
    """
    analyzer = NativeAnalyzer(PYTHON_TOOL_PLUS_HELPERS, "many_helpers.py")
    t0 = time.perf_counter()
    caps = analyzer.extract_mcp_capability_contexts()
    elapsed = (time.perf_counter() - t0) * 1000
    names = {c.name for c in caps}
    assert names == {"add"}, names
    assert elapsed < 500, f"python lazy path too slow: {elapsed:.1f} ms"
