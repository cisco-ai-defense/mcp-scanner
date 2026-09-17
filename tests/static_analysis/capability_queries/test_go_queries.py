# Copyright 2025 Cisco Systems, Inc. and its affiliates
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for ``capability_queries/go/*.scm``.

Go's tree-sitter grammar uses different node names than the JS family
(``selector_expression`` instead of ``member_expression``,
``argument_list`` instead of ``arguments``, ``short_var_declaration``
for ``:=`` bindings, ``var_spec`` for ``var x = ...``). These tests
exercise that the Go-specific patterns capture each shape correctly.
"""

from __future__ import annotations


def test_registrations_match_go_sdk_methods(
    parse_go, go_bundle, run_query
):
    """Both ``mcp.AddTool(server, ...)`` (package-alias receiver) and
    ``server.RegisterPrompt(...)`` (instance receiver) shapes match —
    Go uses ``selector_expression`` callees with a ``field_identifier``
    method name, which the SCM file targets directly."""
    src = """
    package main

    import (
        "context"
        "github.com/modelcontextprotocol/go-sdk/mcp"
    )

    func register() {
        server := mcp.NewServer(&mcp.Implementation{Name: "demo"}, nil)
        mcp.AddTool(server, &mcp.Tool{Name: "add"}, addImpl)
        mcp.AddPrompt(server, &mcp.Prompt{Name: "review"}, reviewImpl)
        server.RegisterTool(&mcp.Tool{Name: "mul"}, mulImpl)
    }
    """
    root, src_b = parse_go(src)
    matches = run_query(go_bundle.registrations, root, src_b)
    methods = sorted(m["method"][0] for m in matches)
    assert methods == ["AddPrompt", "AddTool", "RegisterTool"]


def test_registrations_ignore_unrelated_calls_go(
    parse_go, go_bundle, run_query
):
    """Unrelated method names (``Println``, ``Marshal``) on
    selector_expression callees must NOT match."""
    src = """
    package main

    import "fmt"

    func main() {
        fmt.Println("hello")
        json.Marshal(data)
    }
    """
    root, src_b = parse_go(src)
    matches = run_query(go_bundle.registrations, root, src_b)
    assert matches == []


def test_functions_capture_function_and_method_decl(
    parse_go, go_bundle, run_query
):
    """Both ``function_declaration`` and ``method_declaration`` are
    captured — Go's ``method_declaration`` exposes its name via
    ``field_identifier`` rather than ``identifier``."""
    src = """
    package main

    func bareFn() int { return 1 }

    type S struct{}
    func (s *S) Greet() string { return "hi" }
    """
    root, src_b = parse_go(src)
    matches = run_query(go_bundle.functions, root, src_b)
    names = sorted(m["func_name"][0] for m in matches)
    assert names == ["Greet", "bareFn"]


def test_instantiations_match_short_var_declaration_go(
    parse_go, go_bundle, run_query
):
    """``server := mcp.NewServer(...)`` produces a
    ``short_var_declaration`` that the query captures with @target /
    @receiver / @class."""
    src = """
    package main

    import "github.com/modelcontextprotocol/go-sdk/mcp"

    func main() {
        server := mcp.NewServer(&mcp.Implementation{Name: "demo"}, nil)
        client := mcp.NewClient(&mcp.Implementation{Name: "c"}, nil)
    }
    """
    root, src_b = parse_go(src)
    matches = run_query(go_bundle.instantiations, root, src_b)
    triples = sorted(
        (m["target"][0], m["receiver"][0], m["class"][0])
        for m in matches
        if {"target", "receiver", "class"}.issubset(m.keys())
    )
    assert ("client", "mcp", "NewClient") in triples
    assert ("server", "mcp", "NewServer") in triples


def test_instantiations_match_var_spec_go(parse_go, go_bundle, run_query):
    """``var server = mcp.NewServer(...)`` (the ``var`` form) produces
    a ``var_spec`` that the second pattern in instantiations.scm
    captures."""
    src = """
    package main

    import "github.com/modelcontextprotocol/go-sdk/mcp"

    var server = mcp.NewServer(&mcp.Implementation{Name: "demo"}, nil)
    """
    root, src_b = parse_go(src)
    matches = run_query(go_bundle.instantiations, root, src_b)
    pairs = sorted(
        (m["target"][0], m["class"][0])
        for m in matches
        if "class" in m
    )
    assert pairs == [("server", "NewServer")]
