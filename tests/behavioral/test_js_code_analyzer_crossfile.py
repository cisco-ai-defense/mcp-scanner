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

"""Cross-file capability extraction wiring for JSBehavioralCodeAnalyzer."""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from mcpscanner.core.analyzers.behavioral import js_code_analyzer as jmod
from mcpscanner.core.static_analysis import NativeAnalyzer


class _FakeConfig:
    def __init__(self, llm_provider_api_key: str = "test-key"):
        self.llm_provider_api_key = llm_provider_api_key
        self.llm_model = "gpt-4o-mini"
        self.llm_base_url = ""
        self.llm_api_version = ""


GRAPH_TOOLS_INDEX = """\
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { api } from "./graph-endpoints.js";

const server = new McpServer({ name: "graph", version: "1.0" });

for (const tool of api.endpoints) {
  server.tool(
    tool.alias,
    tool.description,
    tool.schema,
    {},
    async (params) => ({ content: [{ type: "text", text: "ok" }] }),
  );
}
"""

GRAPH_ENDPOINTS_MODULE = """\
export const api = {
  endpoints: [
    { alias: "list-mail", description: "List mail", schema: {} },
    { alias: "get-calendar", description: "Get calendar", schema: {} },
  ],
};
"""


def test_build_directory_call_graphs_expands_imported_endpoint_aliases(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Directory call graphs must resolve ``tool.alias`` from sibling modules."""
    index_path = tmp_path / "graph-tools.ts"
    endpoints_path = tmp_path / "graph-endpoints.ts"
    index_path.write_text(GRAPH_TOOLS_INDEX)
    endpoints_path.write_text(GRAPH_ENDPOINTS_MODULE)

    monkeypatch.setattr(jmod, "AlignmentOrchestrator", MagicMock())
    analyzer = jmod.JSBehavioralCodeAnalyzer(_FakeConfig())
    files = analyzer._find_js_files(str(tmp_path))
    call_graphs = analyzer._build_directory_call_graphs(files)

    assert "typescript" in call_graphs
    caps = NativeAnalyzer(
        GRAPH_TOOLS_INDEX, str(index_path)
    ).extract_mcp_capability_contexts(
        cross_file_analyzer=call_graphs["typescript"]
    )
    names = {c.name for c in caps}
    assert "list-mail" in names, names
    assert "get-calendar" in names, names


def test_analyze_directory_passes_cross_file_analyzer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``analyze(directory)`` must wire cross-file graphs into extraction."""
    index_path = tmp_path / "graph-tools.ts"
    endpoints_path = tmp_path / "graph-endpoints.ts"
    index_path.write_text(GRAPH_TOOLS_INDEX)
    endpoints_path.write_text(GRAPH_ENDPOINTS_MODULE)

    monkeypatch.setattr(jmod, "AlignmentOrchestrator", MagicMock())

    cross_file_seen: list[bool] = []
    original_extract = NativeAnalyzer.extract_mcp_capability_contexts

    def _spy_extract(self, cross_file_analyzer=None):
        cross_file_seen.append(cross_file_analyzer is not None)
        return original_extract(self, cross_file_analyzer=cross_file_analyzer)

    monkeypatch.setattr(
        NativeAnalyzer, "extract_mcp_capability_contexts", _spy_extract
    )

    analyzer = jmod.JSBehavioralCodeAnalyzer(_FakeConfig())
    asyncio.run(analyzer.analyze(str(tmp_path), {}))

    assert cross_file_seen, "expected at least one extraction pass"
    assert any(cross_file_seen), "cross_file_analyzer was never passed"
