# Copyright 2025 Cisco Systems, Inc. and its affiliates
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0

"""Shared test fixtures for capability-query unit tests.

Each test parses a small synthetic snippet, runs one ``.scm`` query
from the shipped bundle, and asserts the capture map matches what the
imperative walker would produce. The fixtures hide the boilerplate of
creating a tree-sitter Parser per language.
"""

from __future__ import annotations

from typing import Callable, Dict, Iterable, List, Tuple

import pytest
from tree_sitter import Language, Node, Parser, QueryCursor

from mcpscanner.core.static_analysis.capability_queries import (
    QueryBundle,
    get_loader,
)


def _ts_text(node: Node, src: bytes) -> str:
    return src[node.start_byte : node.end_byte].decode("utf-8")


@pytest.fixture
def parse_typescript() -> Callable[[str], Tuple[Node, bytes]]:
    """Parse a TS source snippet, returning ``(root_node, source_bytes)``."""
    import tree_sitter_typescript

    lang = Language(tree_sitter_typescript.language_typescript())
    parser = Parser(lang)

    def _parse(src: str) -> Tuple[Node, bytes]:
        b = src.encode("utf-8")
        return parser.parse(b).root_node, b

    return _parse


@pytest.fixture
def parse_javascript() -> Callable[[str], Tuple[Node, bytes]]:
    """Parse a JS source snippet, returning ``(root_node, source_bytes)``."""
    import tree_sitter_javascript

    lang = Language(tree_sitter_javascript.language())
    parser = Parser(lang)

    def _parse(src: str) -> Tuple[Node, bytes]:
        b = src.encode("utf-8")
        return parser.parse(b).root_node, b

    return _parse


@pytest.fixture
def parse_go() -> Callable[[str], Tuple[Node, bytes]]:
    """Parse a Go source snippet, returning ``(root_node, source_bytes)``."""
    import tree_sitter_go

    lang = Language(tree_sitter_go.language())
    parser = Parser(lang)

    def _parse(src: str) -> Tuple[Node, bytes]:
        b = src.encode("utf-8")
        return parser.parse(b).root_node, b

    return _parse


@pytest.fixture
def run_query() -> Callable[..., List[Dict[str, List[str]]]]:
    """Run a query and return capture maps as ``{name: [text, ...]}`` dicts.

    Decoupling from raw ``Node`` objects in the assertions keeps the
    tests resilient to grammar revisions: as long as the captured text
    is right, the test passes.
    """

    def _run(query, root: Node, src: bytes) -> List[Dict[str, List[str]]]:
        cursor = QueryCursor(query)
        out: List[Dict[str, List[str]]] = []
        for _pat_idx, captures in cursor.matches(root):
            entry: Dict[str, List[str]] = {}
            for name, nodes in captures.items():
                entry[name] = [_ts_text(n, src) for n in nodes]
            out.append(entry)
        return out

    return _run


@pytest.fixture
def ts_bundle() -> QueryBundle:
    bundle = get_loader().bundle("typescript")
    assert bundle is not None, "TypeScript query bundle not loaded"
    return bundle


@pytest.fixture
def js_bundle() -> QueryBundle:
    bundle = get_loader().bundle("javascript")
    assert bundle is not None, "JavaScript query bundle not loaded"
    return bundle


@pytest.fixture
def go_bundle() -> QueryBundle:
    bundle = get_loader().bundle("go")
    assert bundle is not None, "Go query bundle not loaded"
    return bundle


def methods_in(matches: Iterable[Dict[str, List[str]]]) -> List[str]:
    """Helper: return the ``@method`` text from each match in order."""
    return [m["method"][0] for m in matches if "method" in m]
