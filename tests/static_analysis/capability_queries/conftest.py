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


def _make_parse_fixture(language_factory: Callable[[], Language]):
    """Build a per-language parse fixture without re-creating the
    tree-sitter Parser/Language objects on every call.

    The factory pattern keeps the fixture body small while still
    binding the language module lazily — importing every grammar at
    module load time would slow down `pytest --collect-only`."""

    def fixture(_request) -> Callable[[str], Tuple[Node, bytes]]:
        lang = language_factory()
        parser = Parser(lang)

        def _parse(src: str) -> Tuple[Node, bytes]:
            b = src.encode("utf-8")
            return parser.parse(b).root_node, b

        return _parse

    return fixture


@pytest.fixture
def parse_kotlin(request) -> Callable[[str], Tuple[Node, bytes]]:
    import tree_sitter_kotlin

    return _make_parse_fixture(lambda: Language(tree_sitter_kotlin.language()))(request)


@pytest.fixture
def parse_java(request) -> Callable[[str], Tuple[Node, bytes]]:
    import tree_sitter_java

    return _make_parse_fixture(lambda: Language(tree_sitter_java.language()))(request)


@pytest.fixture
def parse_csharp(request) -> Callable[[str], Tuple[Node, bytes]]:
    import tree_sitter_c_sharp

    return _make_parse_fixture(lambda: Language(tree_sitter_c_sharp.language()))(request)


@pytest.fixture
def parse_rust(request) -> Callable[[str], Tuple[Node, bytes]]:
    import tree_sitter_rust

    return _make_parse_fixture(lambda: Language(tree_sitter_rust.language()))(request)


@pytest.fixture
def parse_php(request) -> Callable[[str], Tuple[Node, bytes]]:
    import tree_sitter_php

    return _make_parse_fixture(lambda: Language(tree_sitter_php.language_php()))(request)


@pytest.fixture
def parse_ruby(request) -> Callable[[str], Tuple[Node, bytes]]:
    import tree_sitter_ruby

    return _make_parse_fixture(lambda: Language(tree_sitter_ruby.language()))(request)


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


@pytest.fixture
def kotlin_bundle() -> QueryBundle:
    bundle = get_loader().bundle("kotlin")
    assert bundle is not None, "Kotlin query bundle not loaded"
    return bundle


@pytest.fixture
def java_bundle() -> QueryBundle:
    bundle = get_loader().bundle("java")
    assert bundle is not None, "Java query bundle not loaded"
    return bundle


@pytest.fixture
def csharp_bundle() -> QueryBundle:
    bundle = get_loader().bundle("c_sharp")
    assert bundle is not None, "C# query bundle not loaded"
    return bundle


@pytest.fixture
def rust_bundle() -> QueryBundle:
    bundle = get_loader().bundle("rust")
    assert bundle is not None, "Rust query bundle not loaded"
    return bundle


@pytest.fixture
def php_bundle() -> QueryBundle:
    bundle = get_loader().bundle("php")
    assert bundle is not None, "PHP query bundle not loaded"
    return bundle


@pytest.fixture
def ruby_bundle() -> QueryBundle:
    bundle = get_loader().bundle("ruby")
    assert bundle is not None, "Ruby query bundle not loaded"
    return bundle


def methods_in(matches: Iterable[Dict[str, List[str]]]) -> List[str]:
    """Helper: return the ``@method`` text from each match in order."""
    return [m["method"][0] for m in matches if "method" in m]
