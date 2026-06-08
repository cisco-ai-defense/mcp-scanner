# Copyright 2025 Cisco Systems, Inc. and its affiliates
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for ``capability_queries/javascript/*.scm``.

These mirror the TypeScript tests because the JS SCM bodies are
intentionally identical to their TS siblings — the JS grammar exposes
``call_expression``, ``member_expression``, ``property_identifier``,
``arrow_function``, etc. with the same node names. We assert this
equivalence by re-running the same shape-level checks against
``tree-sitter-javascript`` so a future grammar drift would surface.
"""

from __future__ import annotations


def test_registrations_match_high_level_methods_js(
    parse_javascript, js_bundle, run_query
):
    """High-level SDK calls captured under tree-sitter-javascript
    produce the same shape as the TS test asserted."""
    src = """
    server.tool("add", { a: 0, b: 0 }, async () => 1);
    server.registerTool({ name: "mul" }, async () => 2);
    server.addPrompt({ name: "review" }, async () => ({}));
    server.resource("file", "file:///x", async () => ({}));
    """
    root, src_b = parse_javascript(src)
    matches = run_query(js_bundle.registrations, root, src_b)
    methods = sorted(m["method"][0] for m in matches)
    assert methods == ["addPrompt", "registerTool", "resource", "tool"]


def test_low_level_match_setRequestHandler_js(
    parse_javascript, js_bundle, run_query
):
    """``setRequestHandler`` low-level form is captured identically."""
    src = """
    server.setRequestHandler(CallToolRequestSchema, async () => ({}));
    server.onRequest("/foo", async () => ({}));
    """
    root, src_b = parse_javascript(src)
    matches = run_query(js_bundle.low_level, root, src_b)
    assert len(matches) == 1
    assert matches[0]["method"] == ["setRequestHandler"]


def test_functions_named_and_arrow_js(
    parse_javascript, js_bundle, run_query
):
    src = """
    function bareFn() { return 1; }
    const arrowFn = (x) => x * 2;
    class C { greet() { return "hi"; } }
    """
    root, src_b = parse_javascript(src)
    matches = run_query(js_bundle.functions, root, src_b)
    names = sorted(m["func_name"][0] for m in matches)
    assert "bareFn" in names
    assert "arrowFn" in names
    assert "greet" in names


def test_instantiations_new_expression_js(
    parse_javascript, js_bundle, run_query
):
    src = """
    const a = new McpServer({ name: "x" });
    const b = new mcp.Server({ name: "y" });
    """
    root, src_b = parse_javascript(src)
    matches = run_query(js_bundle.instantiations, root, src_b)
    pairs = sorted(
        (m["target"][0], m["class"][0]) for m in matches if "class" in m
    )
    assert ("a", "McpServer") in pairs
    assert ("b", "Server") in pairs
