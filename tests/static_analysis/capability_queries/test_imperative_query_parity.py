# Copyright 2025 Cisco Systems, Inc. and its affiliates
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0

"""Parity test: query-backed walkers produce the same output as the
imperative walkers they replace.

The migration kept both paths on the class so we can compare them on
identical input. This guards against silent regressions when someone
edits one path but not the other and relies only on end-to-end
fixtures.
"""

from __future__ import annotations

import pytest
from tree_sitter import Language, Parser

from mcpscanner.core.static_analysis import capability_queries as cq
from mcpscanner.core.static_analysis.capability_detector import (
    CapabilityDetector,
)
from mcpscanner.core.static_analysis.native_analyzer import NativeAnalyzer


def _parse(language: str, source: str):
    """Return ``(parser, root_node, source_bytes)`` for one of the
    languages used by these tests."""
    if language == "typescript":
        import tree_sitter_typescript

        lang = Language(tree_sitter_typescript.language_typescript())
    elif language == "javascript":
        import tree_sitter_javascript

        lang = Language(tree_sitter_javascript.language())
    elif language == "go":
        import tree_sitter_go

        lang = Language(tree_sitter_go.language())
    elif language == "kotlin":
        import tree_sitter_kotlin

        lang = Language(tree_sitter_kotlin.language())
    elif language == "java":
        import tree_sitter_java

        lang = Language(tree_sitter_java.language())
    elif language == "c_sharp":
        import tree_sitter_c_sharp

        lang = Language(tree_sitter_c_sharp.language())
    elif language == "rust":
        import tree_sitter_rust

        lang = Language(tree_sitter_rust.language())
    elif language == "php":
        import tree_sitter_php

        lang = Language(tree_sitter_php.language_php())
    elif language == "ruby":
        import tree_sitter_ruby

        lang = Language(tree_sitter_ruby.language())
    else:
        raise AssertionError(f"unsupported parity language: {language}")

    parser = Parser(lang)
    src_b = source.encode("utf-8")
    tree = parser.parse(src_b)
    return parser, tree.root_node, src_b


TS_FIXTURE = """
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const server = new McpServer({ name: "demo", version: "1.0.0" });
const helper = (x: number) => x * 2;
const addImpl = async ({ a, b }: any) => a + b;

server.tool("add", { a: 0, b: 0 }, addImpl);
server.registerTool({ name: "mul" }, async ({ a, b }: any) => a * b);
server.addPrompt({ name: "review" }, async () => ({}));
server.resource("file", "file:///x", async () => ({}));
server.setRequestHandler(CallToolRequestSchema, async (req: any) => ({}));

class Helper {
  greet() { return "hi"; }
}
"""


JS_FIXTURE = """
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

const server = new McpServer({ name: "demo" });
const addImpl = async (args) => args.value + 1;

server.tool("add", { value: 0 }, addImpl);
server.registerTool({ name: "mul" }, async (args) => args.value * 2);
"""


GO_FIXTURE = """
package main

import (
    "context"
    "github.com/modelcontextprotocol/go-sdk/mcp"
)

func register() {
    server := mcp.NewServer(&mcp.Implementation{Name: "demo"}, nil)
    mcp.AddTool(server, &mcp.Tool{Name: "add"}, addImpl)
    mcp.AddPrompt(server, &mcp.Prompt{Name: "review"}, reviewImpl)
}
"""


# ---------------------------------------------------------------------
# Annotation-driven languages: only ``functions.scm`` is shipped, so
# parity is checked for the function-name index and (separately) the
# annotation index. ``registrations.scm`` doesn't apply — these
# languages don't use call-site MCP registration.
# ---------------------------------------------------------------------

JAVA_FIXTURE = """
package demo;

import org.springframework.ai.tool.annotation.Tool;

public class Calc {
    private double normalize(double x) { return x; }

    @Tool(description = "Add two numbers")
    public double add(double a, double b) { return normalize(a) + b; }

    public Calc() {}
}
"""

CSHARP_FIXTURE = """
using ModelContextProtocol.Server;

[McpServerToolType]
public static class Calc {
    [McpServerTool, Description("Add two numbers")]
    public static double Add(double a, double b) => a + b;

    public Calc() {}
}
"""

RUST_FIXTURE = """
use rmcp::{tool, tool_router};

struct Calculator;

fn helper(x: f64) -> f64 { x }

#[tool_router]
impl Calculator {
    #[tool(description = "Add")]
    fn add(&self, a: f64, b: f64) -> f64 { helper(a) + b }
}
"""

PHP_FIXTURE = """<?php
use PhpMcp\\Server\\Attributes\\McpTool;

class Calc {
    private function helper(float $x): float { return $x; }

    #[McpTool(name: "add", description: "Add")]
    public function add(float $a, float $b): float {
        return $this->helper($a) + $b;
    }
}
"""

RUBY_FIXTURE = """
require "mcp"

def helper(x); x; end

# @tool name: "add", description: "Add"
def add(a, b); helper(a) + b; end
"""

KOTLIN_FIXTURE = """
package demo

import io.modelcontextprotocol.kotlin.sdk.server.Server

fun helper(x: Double): Double = x

fun register(server: Server) {
    server.addTool(
        name = "add",
        description = "Add two numbers",
    ) { request ->
        helper(1.0)
    }
}
"""

ALL_LANGUAGE_FIXTURES = [
    ("typescript", "TS_FIXTURE", "/tmp/parity.ts"),
    ("javascript", "JS_FIXTURE", "/tmp/parity.js"),
    ("go", "GO_FIXTURE", "/tmp/parity.go"),
    ("kotlin", "KOTLIN_FIXTURE", "/tmp/parity.kt"),
    ("java", "JAVA_FIXTURE", "/tmp/Parity.java"),
    ("c_sharp", "CSHARP_FIXTURE", "/tmp/Parity.cs"),
    ("rust", "RUST_FIXTURE", "/tmp/parity.rs"),
    ("php", "PHP_FIXTURE", "/tmp/parity.php"),
    ("ruby", "RUBY_FIXTURE", "/tmp/parity.rb"),
]


def _fixture_source(name: str) -> str:
    return globals()[name]


def _registration_signature(reg):
    """Compare-friendly key — handler/name fields, not Node identity.

    ``None`` is normalised to a ``""`` sentinel so a list of signatures
    is sortable across Python's strict ``None < str`` rule.
    """
    none_to_empty = lambda v: "" if v is None else v
    return (
        none_to_empty(reg.get("capability")),
        none_to_empty(reg.get("name")),
        none_to_empty(reg.get("handler_name")),
        none_to_empty(reg.get("template_subtype")),
        reg.get("handler_node") is not None,
    )


@pytest.mark.parametrize(
    "language,fixture_name,filename",
    [
        ("typescript", "TS_FIXTURE", "/tmp/parity.ts"),
        ("javascript", "JS_FIXTURE", "/tmp/parity.js"),
        ("go", "GO_FIXTURE", "/tmp/parity.go"),
        # Kotlin: the only other language with call-site registration.
        # The fixture exercises the trailing-lambda shape — the most
        # demanding case because it requires the dual-pattern
        # ``registrations.scm`` and the merge-by-call-signature logic
        # in ``_collect_q_registrations``.
        ("kotlin", "KOTLIN_FIXTURE", "/tmp/parity.kt"),
    ],
)
def test_registrations_parity(language, fixture_name, filename):
    """Imperative and query paths must return the same registration set."""
    source = _fixture_source(fixture_name)
    analyzer = NativeAnalyzer(source, filename)
    detector = CapabilityDetector(analyzer)
    _, root, _ = _parse(language, source)

    imports = analyzer._ts_extract_imports(root)
    trusted = detector._collect_mcp_instances(root, imports)

    imp = detector._ts_find_mcp_registrations_imperative(root, trusted)
    bundle = cq.get_bundle(language)
    assert bundle is not None, f"no query bundle for {language}"
    qry = detector._ts_find_mcp_registrations_q(root, trusted, bundle)

    imp_set = sorted(_registration_signature(r) for r in imp)
    qry_set = sorted(_registration_signature(r) for r in qry)
    assert imp_set == qry_set, (
        f"{language}: imperative vs query mismatch\n"
        f"  imp: {imp_set}\n  qry: {qry_set}"
    )


@pytest.mark.parametrize(
    "language,fixture_name,filename", ALL_LANGUAGE_FIXTURES
)
def test_function_index_parity(language, fixture_name, filename):
    """The function-name index produced by the imperative walk and the
    query walk must contain the same names (definitions can differ by
    Node identity but the names must agree).

    Covers all 9 query-supported languages — the migration is only
    safe if the new ``.scm`` files emit the same function-name set
    that the imperative walker would have indexed.
    """
    source = _fixture_source(fixture_name)
    analyzer = NativeAnalyzer(source, filename)
    detector = CapabilityDetector(analyzer)
    _, root, _ = _parse(language, source)

    func_types = analyzer.FUNCTION_NODE_TYPES.get(language, set())
    bundle = cq.get_bundle(language)
    assert bundle is not None

    imp = detector._ts_build_function_index_imperative(root, func_types)
    qry = detector._ts_build_function_index_q(root, func_types, bundle.functions)

    assert sorted(imp.keys()) == sorted(qry.keys()), (
        f"{language}: function-index name mismatch\n"
        f"  imp: {sorted(imp.keys())}\n  qry: {sorted(qry.keys())}"
    )


@pytest.mark.parametrize(
    "language,fixture_name,filename", ALL_LANGUAGE_FIXTURES
)
def test_annotation_index_parity(language, fixture_name, filename):
    """Annotation index parity for every query-supported language.

    The query path delegates to the same per-function annotation
    collector the imperative path uses, so the two indexes must agree
    on every (start_byte → annotations) entry.
    """
    source = _fixture_source(fixture_name)
    analyzer = NativeAnalyzer(source, filename)
    detector = CapabilityDetector(analyzer)
    _, root, _ = _parse(language, source)

    func_types = analyzer.FUNCTION_NODE_TYPES.get(language, set())

    # Direct calls to the two implementations bypass the cache so
    # we exercise both paths against the same root node.
    bundle = cq.get_bundle(language)
    assert bundle is not None and bundle.functions is not None

    qry = detector._ts_build_annotation_index_q(
        root, func_types, bundle.functions
    )

    # Reproduce the imperative walk inline because the public method
    # now dispatches to the query path automatically.
    from mcpscanner.core.static_analysis.capability_detector import (
        _TS_NON_FUNCTION_NODE_TYPES,
    )

    imp: dict = {}

    def visit(node):
        if node.type in func_types and node.type not in _TS_NON_FUNCTION_NODE_TYPES:
            annotations = detector._ts_collect_function_annotations(node)
            if annotations:
                imp[node.start_byte] = annotations
        for child in node.children:
            visit(child)

    visit(root)

    assert imp == qry, (
        f"{language}: annotation index mismatch\n"
        f"  imp keys: {sorted(imp.keys())}\n"
        f"  qry keys: {sorted(qry.keys())}\n"
        f"  imp: {imp}\n  qry: {qry}"
    )


@pytest.mark.parametrize(
    "language,fixture_name,filename",
    [
        ("typescript", "TS_FIXTURE", "/tmp/parity.ts"),
        ("javascript", "JS_FIXTURE", "/tmp/parity.js"),
        ("go", "GO_FIXTURE", "/tmp/parity.go"),
        # Kotlin ships ``instantiations.scm``; the others (Java, C#,
        # Rust, PHP, Ruby) don't, so they fall through to the
        # imperative path entirely and there's nothing to compare.
        ("kotlin", "KOTLIN_FIXTURE", "/tmp/parity.kt"),
    ],
)
def test_instances_parity(language, fixture_name, filename):
    """Trusted-receiver sets from the imperative and query paths must
    match. Both paths get the same (sdk_classes, sdk_aliases) input
    because Stage 1 is shared."""
    source = _fixture_source(fixture_name)
    analyzer = NativeAnalyzer(source, filename)
    detector = CapabilityDetector(analyzer)
    _, root, _ = _parse(language, source)

    imports = analyzer._ts_extract_imports(root)
    # ``_collect_mcp_instances`` runs Stage 1 + Stage 2; we run the
    # full pipeline twice — once with the query bundle force-disabled
    # — and compare. Caching the two results requires resetting the
    # loader's bundle map between runs.
    loader = cq.get_loader()
    saved = loader._bundles
    try:
        loader._bundles = {language: None}
        imp_trusted = detector._collect_mcp_instances(root, imports)
        loader._bundles = {}
        qry_trusted = detector._collect_mcp_instances(root, imports)
    finally:
        loader._bundles = saved

    assert imp_trusted == qry_trusted, (
        f"{language}: trusted-receiver mismatch\n"
        f"  imp: {sorted(imp_trusted)}\n  qry: {sorted(qry_trusted)}"
    )
