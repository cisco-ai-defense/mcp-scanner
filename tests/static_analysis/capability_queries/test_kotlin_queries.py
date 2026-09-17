# Copyright 2025 Cisco Systems, Inc. and its affiliates
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for ``capability_queries/kotlin/*.scm``.

Kotlin is the only language outside JS/TS/Go that uses *call-site*
MCP registration (``server.addTool(...) { req -> ... }``), so it
needs ``registrations.scm`` and ``instantiations.scm`` in addition
to ``functions.scm``. We exercise the trailing-lambda variant
explicitly because that's the canonical SDK shape and the only one
that requires the dual-pattern dance described in
``registrations.scm``.
"""

from __future__ import annotations


def test_registrations_match_bare_addtool(parse_kotlin, kotlin_bundle, run_query):
    """A registration without a trailing lambda still matches.

    Kotlin SDK callers occasionally pass a method reference instead of
    a lambda: ``server.addTool(name = "add", handler = ::add)``. The
    bare-call pattern (pattern 1 in ``registrations.scm``) covers
    this case.
    """
    src = """
    package demo
    fun register(server: Any) {
        server.addTool(name = "add", handler = ::add)
    }
    """
    root, src_b = parse_kotlin(src)
    matches = run_query(kotlin_bundle.registrations, root, src_b)
    assert len(matches) == 1
    m = matches[0]
    assert m["method"] == ["addTool"]
    assert m["receiver"] == ["server"]
    # Bare form: no @lambda capture.
    assert "lambda" not in m


def test_registrations_match_trailing_lambda(
    parse_kotlin, kotlin_bundle, run_query
):
    """The canonical Kotlin SDK form: ``server.addTool(...) { req -> }``.

    tree-sitter-kotlin wraps the call in an outer ``call_expression``
    whose first child is the inner registration call and whose
    sibling is an ``annotated_lambda``. The wrapped pattern (pattern
    2 in ``registrations.scm``) captures @lambda; the bare pattern
    (pattern 1) ALSO matches because the inner call still has the
    ``call_expression { navigation_expression, value_arguments }``
    shape. Both matches share the same ``@call`` (the inner call),
    so we expect to see two raw matches here — the consumer's
    deduplication is tested in test_imperative_query_parity.
    """
    src = """
    package demo
    fun register(server: Any) {
        server.addTool(name = "add") { request ->
            request
        }
    }
    """
    root, src_b = parse_kotlin(src)
    matches = run_query(kotlin_bundle.registrations, root, src_b)
    # Two raw matches: bare + wrapped. ``_collect_q_registrations``
    # merges them so the consumer sees one logical registration.
    assert len(matches) == 2
    methods = [m["method"][0] for m in matches]
    assert methods == ["addTool", "addTool"]
    # Exactly one match carries the trailing lambda.
    with_lambda = [m for m in matches if "lambda" in m]
    assert len(with_lambda) == 1


def test_functions_match_named_declarations_only(
    parse_kotlin, kotlin_bundle, run_query
):
    """``functions.scm`` exposes named ``function_declaration`` plus
    the unnamed callable shapes (lambdas, secondary constructors)
    needed by the annotation pass. Only named ones produce a
    ``@func_name`` capture."""
    src = """
    package demo
    fun helper(x: Int): Int = x
    class C(name: String) {
        constructor(other: Int) : this("x") {}
        fun method() {}
    }
    val f = { x: Int -> x }
    val g = fun(y: Int) = y
    """
    root, src_b = parse_kotlin(src)
    matches = run_query(kotlin_bundle.functions, root, src_b)

    named = [m["func_name"][0] for m in matches if "func_name" in m]
    assert sorted(named) == ["helper", "method"]

    # All matches expose @func_def regardless of name presence.
    assert all("func_def" in m for m in matches)


def test_instantiations_match_val_and_var(
    parse_kotlin, kotlin_bundle, run_query
):
    """``val server = Server()`` and ``var server = Server()`` parse
    to the same ``property_declaration`` shape — they only differ in
    the unnamed leading keyword token, which the query doesn't
    constrain."""
    src = """
    package demo
    val s1 = Server()
    var s2 = Server(prefix = "x")
    """
    root, src_b = parse_kotlin(src)
    matches = run_query(kotlin_bundle.instantiations, root, src_b)
    targets = sorted(m["target"][0] for m in matches)
    classes = sorted(m["class"][0] for m in matches)
    assert targets == ["s1", "s2"]
    assert classes == ["Server", "Server"]
