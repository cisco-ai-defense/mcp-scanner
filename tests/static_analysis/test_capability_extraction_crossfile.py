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

"""Cross-file handler resolution tests (Gap 2).

When a registration's handler is a bare identifier defined in a
different file, the extractor must consult the cross-file call graph
(``CallGraphAnalyzer`` for Python, ``TreeSitterCallGraphAnalyzer`` for
the rest) before falling through to an unresolved stub.
"""

from pathlib import Path

import pytest

from mcpscanner.core.static_analysis import NativeAnalyzer
from mcpscanner.core.static_analysis.interprocedural.treesitter_call_graph import (
    TreeSitterCallGraphAnalyzer,
)


INDEX_TS = """\
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { addHandler } from "./tools/add";

const server = new McpServer({ name: "demo", version: "1.0" });
server.registerTool("add", { description: "Add two numbers" }, addHandler);
"""

ADD_TS = """\
export async function addHandler(input: { a: number; b: number }) {
  return input.a + input.b;
}
"""


def test_crossfile_handler_resolution_via_callgraph(tmp_path: Path) -> None:
    """Handler defined in ``tools/add.ts``, registered in ``index.ts``,
    must surface via the cross-file call graph (Gap 2)."""
    (tmp_path / "tools").mkdir()
    index_path = tmp_path / "index.ts"
    add_path = tmp_path / "tools" / "add.ts"
    index_path.write_text(INDEX_TS)
    add_path.write_text(ADD_TS)

    cga = TreeSitterCallGraphAnalyzer("typescript")
    cga.add_file(index_path, INDEX_TS)
    cga.add_file(add_path, ADD_TS)
    cga.build_call_graph()

    analyzer = NativeAnalyzer(INDEX_TS, str(index_path))
    caps = analyzer.extract_mcp_capability_contexts(cross_file_analyzer=cga)
    assert len(caps) == 1, [c.name for c in caps]
    cap = caps[0]
    # Cross-file resolution surfaces the registered name plus a tag.
    tags = cap.decorator_types
    assert any("registration.cross_file" in t for t in tags), tags
    assert "addHandler" in cap.name or "add" in cap.name


def test_crossfile_unresolved_handler_emits_stub() -> None:
    """When neither the in-file index nor the cross-file call graph
    locates the handler, an unresolved stub is emitted (Gap 8) so
    the capability is still visible to the LLM."""
    src = """\
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

const server = new McpServer({ name: "demo", version: "1.0" });
server.registerTool("missing", { description: "x" }, missingHandler);
"""
    analyzer = NativeAnalyzer(src, "missing.ts")
    caps = analyzer.extract_mcp_capability_contexts()
    assert len(caps) == 1, [c.name for c in caps]
    cap = caps[0]
    tags = cap.decorator_types
    assert any("registration.unresolved" in t for t in tags), tags
