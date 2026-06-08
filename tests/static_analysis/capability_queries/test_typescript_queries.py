# Copyright 2025 Cisco Systems, Inc. and its affiliates
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for ``capability_queries/typescript/*.scm``.

Each test feeds a small synthetic TypeScript source snippet to the
parser, runs one of the shipped queries, and asserts the capture map.
These complement the end-to-end fixture-based tests that exercise the
full ``CapabilityDetector`` pipeline — here we want fast, focused
coverage that catches grammar / pattern regressions without invoking
the full detector machinery.
"""

from __future__ import annotations


def test_registrations_match_high_level_methods(
    parse_typescript, ts_bundle, run_query
):
    """High-level SDK calls (tool / registerTool / addPrompt / resource)
    are all captured with consistent receiver / method / args / call."""
    src = """
    server.tool("add", { a: 0, b: 0 }, async () => 1);
    server.registerTool({ name: "mul" }, async () => 2);
    server.addPrompt({ name: "review" }, async () => ({}));
    server.resource("file", "file:///x", async () => ({}));
    """
    root, src_b = parse_typescript(src)
    matches = run_query(ts_bundle.registrations, root, src_b)

    methods = sorted(m["method"][0] for m in matches)
    assert methods == ["addPrompt", "registerTool", "resource", "tool"]
    # Every match must have @receiver, @method, @args, and @call captured.
    required = {"receiver", "method", "args", "call"}
    for m in matches:
        assert required.issubset(m.keys()), m


def test_registrations_match_resource_template_variants(
    parse_typescript, ts_bundle, run_query
):
    """Template variants (registerResourceTemplate, addPromptTemplate)
    are admitted by the same query — capability normalization happens
    in Python, not in the SCM."""
    src = """
    server.registerResourceTemplate({ name: "files" }, async () => ({}));
    server.addPromptTemplate({ name: "p" }, async () => ({}));
    """
    root, src_b = parse_typescript(src)
    matches = run_query(ts_bundle.registrations, root, src_b)
    assert len(matches) == 2
    methods = sorted(m["method"][0] for m in matches)
    assert methods == ["addPromptTemplate", "registerResourceTemplate"]


def test_registrations_ignore_unrelated_methods(
    parse_typescript, ts_bundle, run_query
):
    """Methods not in the MCP allow-list (``add``, ``run``, ...) must
    NOT match — the query's ``#match?`` predicate is the safety net."""
    src = """
    server.add(1, 2);
    server.run();
    list.tool;            // property access (not a call)
    arr.push(item);
    """
    root, src_b = parse_typescript(src)
    matches = run_query(ts_bundle.registrations, root, src_b)
    assert matches == []


def test_low_level_matches_setRequestHandler_only(
    parse_typescript, ts_bundle, run_query
):
    """``low_level.scm`` matches *only* setRequestHandler. Unrelated
    handlers (``onRequest``, ``addHandler``) are ignored; the schema
    identifier is intentionally left to Python to interpret."""
    src = """
    server.setRequestHandler(CallToolRequestSchema, async () => ({}));
    server.setRequestHandler(Schemas.ListPromptsRequestSchema, async () => ({}));
    server.onRequest("/foo", async () => ({}));
    server.addHandler(handler);
    """
    root, src_b = parse_typescript(src)
    matches = run_query(ts_bundle.low_level, root, src_b)
    assert len(matches) == 2
    for m in matches:
        assert m["method"] == ["setRequestHandler"]
        assert "args" in m
        assert "call" in m


def test_functions_index_captures_named_functions(
    parse_typescript, ts_bundle, run_query
):
    """All named-function shapes (declaration / expression / method)
    surface a ``func_name`` + ``func_def`` capture pair."""
    src = """
    function bareFn() { return 1; }
    const namedFE = function inner() { return 2; };
    class C { greet() { return "hi"; } }
    """
    root, src_b = parse_typescript(src)
    matches = run_query(ts_bundle.functions, root, src_b)
    names = sorted(m["func_name"][0] for m in matches)
    # ``namedFE`` is captured twice: once as the function_expression's
    # own name (``inner``) and once as the variable_declarator's name.
    assert "bareFn" in names
    assert "greet" in names
    assert "namedFE" in names or "inner" in names
    for m in matches:
        assert "func_def" in m


def test_functions_index_captures_arrow_assignments(
    parse_typescript, ts_bundle, run_query
):
    """``const fn = (...) => {...}`` and re-assignment forms both
    surface the local binding name as ``func_name``."""
    src = """
    const arrowFn = (x: number) => x * 2;
    let asyncArrow = async (n: number) => n + 1;
    var maybe = function (n: number) { return n; };
    reassign = (x: number) => x;
    """
    root, src_b = parse_typescript(src)
    matches = run_query(ts_bundle.functions, root, src_b)
    names = sorted(m["func_name"][0] for m in matches)
    assert "arrowFn" in names
    assert "asyncArrow" in names
    assert "maybe" in names
    assert "reassign" in names


def test_instantiations_match_new_expression(
    parse_typescript, ts_bundle, run_query
):
    """``new McpServer(...)`` and ``new mcp.Server(...)`` both surface
    ``@target`` (local name) + ``@class`` (constructor leaf)."""
    src = """
    const a = new McpServer({ name: "x" });
    const b = new mcp.Server({ name: "y" });
    let c = new SomeOther();
    """
    root, src_b = parse_typescript(src)
    matches = run_query(ts_bundle.instantiations, root, src_b)
    pairs = sorted(
        (m["target"][0], m["class"][0]) for m in matches if "class" in m
    )
    assert ("a", "McpServer") in pairs
    assert ("b", "Server") in pairs
    assert ("c", "SomeOther") in pairs


def test_instantiations_ignore_non_call_rhs(
    parse_typescript, ts_bundle, run_query
):
    """Bindings whose RHS is not a constructor / call (``= 42``,
    ``= []``) must not match — they cannot bind an MCP instance."""
    src = """
    const x = 42;
    let y = "hello";
    const z = [1, 2, 3];
    """
    root, src_b = parse_typescript(src)
    matches = run_query(ts_bundle.instantiations, root, src_b)
    assert matches == []
