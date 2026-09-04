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


# Synthetic ~250 KB TypeScript fixture used by the tree-walk
# perf guards. We pick 250 KB rather than 1 MB so the test runs in
# under a second on CI; the tree-walk reduction percentages are scale-
# invariant (both paths walk the same nodes).
_TS_PERF_CHUNK = """
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const server%(idx)d = new McpServer({ name: "demo%(idx)d", version: "1.0" });
const handler%(idx)d = async (args: any) => args.value + 1;
const helper%(idx)d = (x: number) => x * 2;

server%(idx)d.tool("add%(idx)d", { value: 0 }, handler%(idx)d);
server%(idx)d.registerTool({ name: "mul%(idx)d" }, async ({ value }: any) => value * 2);
server%(idx)d.addPrompt({ name: "review%(idx)d" }, async () => ({}));
server%(idx)d.resource("file%(idx)d", "file:///x", async () => ({}));
server%(idx)d.setRequestHandler(CallToolRequestSchema, async (req: any) => ({}));

class C%(idx)d {
  greet() { return "hi%(idx)d"; }
  bye() { return "bye%(idx)d"; }
}
"""


def _build_ts_perf_source(target_bytes: int) -> str:
    parts: list[str] = []
    i = 0
    while sum(len(p) for p in parts) < target_bytes:
        parts.append(_TS_PERF_CHUNK % {"idx": i})
        i += 1
    return "".join(parts)


def _median(timings: list[float]) -> float:
    return sorted(timings)[len(timings) // 2]


@pytest.mark.slow
def test_query_path_within_reasonable_bound_on_1mb_ts() -> None:
    """Tree-walk perf guard on a representative 1 MB TS file.

    The follow-up issue's stretch goal was ">=30% reduction in
    tree-walk time" but empirical measurement on a warmed Python
    interpreter showed the query path is roughly perf-neutral on the
    registrations walker — the bottleneck is
    ``_ts_parse_registration_args`` (Python-level argument decoding,
    shared by both paths), not the outer tree walk that queries
    replace. The function-index walker shows a small (~10%)
    improvement; the instance walker is roughly even.

    The migration's value is **code quality** — declarative ``.scm``
    files vs nested imperative walks, easier unit testing, localized
    extension points — not raw speed. Tree walks are <5% of total
    scan time on real MCP servers, so even the larger fixtures
    studied here have negligible end-to-end impact.

    This perf guard catches the failure mode where someone
    accidentally re-introduces an O(N²) walk in the query glue. It
    asserts the query path is within 2x of the imperative path on a
    1 MB fixture.

    Marked ``slow`` so casual ``pytest`` invocations skip it.
    """
    pytest.importorskip("tree_sitter_typescript")
    from tree_sitter import Language, Parser
    import tree_sitter_typescript

    from mcpscanner.core.static_analysis import capability_queries as cq
    from mcpscanner.core.static_analysis.capability_detector import (
        CapabilityDetector,
    )

    src = _build_ts_perf_source(1_000_000)
    lang = Language(tree_sitter_typescript.language_typescript())
    parser = Parser(lang)
    tree = parser.parse(src.encode("utf-8"))
    root = tree.root_node

    analyzer = NativeAnalyzer(src, "perf.ts")
    detector = CapabilityDetector(analyzer)
    imports = analyzer._ts_extract_imports(root)
    trusted = detector._collect_mcp_instances(root, imports)
    bundle = cq.get_bundle("typescript")
    assert bundle is not None and bundle.registrations is not None

    func_types = analyzer.FUNCTION_NODE_TYPES.get("typescript", set())

    def _bench(fn, *, warmup: int = 3, repeats: int = 5) -> float:
        for _ in range(warmup):
            fn()
        timings = []
        for _ in range(repeats):
            t0 = time.perf_counter()
            fn()
            timings.append(time.perf_counter() - t0)
        return _median(timings)

    # All three migrated walkers, summed — that's the budget the
    # proposal originally targeted. Function-index walk is the only
    # one with a real win; the others are neutral.
    def total_imperative() -> float:
        regs = _bench(
            lambda: detector._ts_find_mcp_registrations_imperative(
                root, trusted
            )
        )
        funcs = _bench(
            lambda: detector._ts_build_function_index_imperative(
                root, func_types
            )
        )
        return regs + funcs

    def total_query() -> float:
        regs = _bench(
            lambda: detector._ts_find_mcp_registrations_q(
                root, trusted, bundle
            )
        )
        funcs = _bench(
            lambda: detector._ts_build_function_index_q(
                root, func_types, bundle.functions
            )
        )
        return regs + funcs

    imp = total_imperative()
    qry = total_query()

    # Sanity: both paths must produce the same registration count on
    # the synthetic fixture, otherwise the timing comparison is
    # meaningless.
    imp_regs = detector._ts_find_mcp_registrations_imperative(root, trusted)
    qry_regs = detector._ts_find_mcp_registrations_q(root, trusted, bundle)
    assert len(imp_regs) == len(qry_regs)
    imp_funcs = detector._ts_build_function_index_imperative(root, func_types)
    qry_funcs = detector._ts_build_function_index_q(
        root, func_types, bundle.functions
    )
    assert sorted(imp_funcs.keys()) == sorted(qry_funcs.keys())

    # Anti-regression bound: query path must stay within 2x of
    # imperative. Locally we see roughly 1.1-1.2x.
    ratio = qry / imp
    assert ratio <= 2.0, (
        f"query path ratio {ratio:.2f}x  imp={imp*1000:.1f}ms qry={qry*1000:.1f}ms"
    )
