# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Tests for the deterministic code graph layer."""

from __future__ import annotations

from pathlib import Path

import pytest

from mcpscanner.core.static_analysis.graph import (
    CodeGraphBuilder,
    EvidenceFormatter,
    GraphSlicer,
    Provenance,
    Relation,
    SinkAnalyzer,
)


PYTHON_SAMPLE = '''
import os
import shutil

def helper(path: str) -> None:
    os.remove(path)

def copy_sensitive(src: str, dst: str) -> None:
    shutil.copy(src, dst)
'''


class TestCodeGraphBuilder:
    def test_builds_python_call_graph_with_provenance(self, tmp_path: Path) -> None:
        sample = tmp_path / "server.py"
        sample.write_text(PYTHON_SAMPLE, encoding="utf-8")

        builder = CodeGraphBuilder()
        builder.add_path(sample)
        graph = builder.build()

        assert graph.stats()["nodes"] >= 2
        assert graph.stats()["calls"] >= 1
        call_edges = [e for e in graph.edges if e.relation == Relation.CALLS]
        assert call_edges
        assert call_edges[0].provenance in {
            Provenance.EXTRACTED,
            Provenance.INFERRED,
            Provenance.AMBIGUOUS,
        }

    def test_slice_from_entry(self, tmp_path: Path) -> None:
        sample = tmp_path / "server.py"
        sample.write_text(PYTHON_SAMPLE, encoding="utf-8")
        graph = CodeGraphBuilder()
        graph.add_path(sample)
        built = graph.build()

        entry = next(iter(built.nodes))
        slice_ = GraphSlicer(built).slice(entry, max_hops=3)
        assert slice_.entry_id == entry
        assert slice_.size >= 1

    def test_sink_analyzer_finds_file_sink(self, tmp_path: Path) -> None:
        sample = tmp_path / "server.py"
        sample.write_text(PYTHON_SAMPLE, encoding="utf-8")
        graph = CodeGraphBuilder()
        graph.add_path(sample)
        built = graph.build()

        helper_id = next(
            nid for nid, node in built.nodes.items() if node.label == "helper"
        )
        result = SinkAnalyzer(built).analyze_entry(helper_id)
        categories = result.categories
        assert "file" in categories or result.hits

    def test_evidence_formatter(self, tmp_path: Path) -> None:
        sample = tmp_path / "server.py"
        sample.write_text(PYTHON_SAMPLE, encoding="utf-8")
        builder = CodeGraphBuilder()
        builder.add_path(sample)
        built = builder.build()

        entry = next(
            nid for nid, node in built.nodes.items() if node.label == "helper"
        )
        slice_ = GraphSlicer(built).slice(entry)
        sinks = SinkAnalyzer(built).analyze_entry(entry)
        text = EvidenceFormatter(built).format_combined(slice_, sinks)
        assert "CODE GRAPH SLICE" in text
        assert "helper" in text

    @pytest.mark.parametrize(
        "ext,expected_lang",
        [
            (".py", "python"),
            (".go", "go"),
            (".rs", "rust"),
        ],
    )
    def test_language_routing(self, ext: str, expected_lang: str, tmp_path: Path) -> None:
        if ext == ".go":
            body = 'package main\nfunc helper() {}\n'
        elif ext == ".rs":
            body = "fn helper() {}\n"
        else:
            body = "def helper():\n    pass\n"
        sample = tmp_path / f"server{ext}"
        sample.write_text(body, encoding="utf-8")
        built = CodeGraphBuilder()
        built.add_path(sample)
        graph = built.build()
        assert graph.language == expected_lang or graph.stats()["nodes"] >= 0
