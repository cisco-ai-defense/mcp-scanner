# Copyright 2025 Cisco Systems, Inc. and its affiliates
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the annotation-driven languages: Java / C# / Rust /
PHP / Ruby.

These languages don't ship ``registrations.scm`` because their MCP
SDKs use *attribute / annotation / comment* markers attached to
function declarations rather than ``server.tool(...)`` call sites.
The only query shipped is ``functions.scm`` which feeds both the
function-name index and the per-function annotation collector.

Each test parses a tiny snippet that includes the canonical SDK
attribute (``@Tool``, ``[McpServerTool]``, ``#[tool]``,
``#[McpTool]``, ``# @tool``) plus a non-MCP helper, and asserts
that the query captures every function-shaped node — *including*
the one carrying the SDK marker. Whether the marker classifies the
function as MCP-relevant is the annotation collector's job, not
the query's.
"""

from __future__ import annotations


# ----------------------------------------------------------------------
# Java: ``@Tool`` annotations from Spring AI's MCP integration. The
# annotation lives inside the method's ``modifiers`` child, so it
# isn't visible in the query — but the function-name index has to
# admit the method so the annotation collector can find it.
# ----------------------------------------------------------------------


def test_java_functions_capture_methods_and_constructors(
    parse_java, java_bundle, run_query
):
    src = """
    package demo;
    public class Calc {
        @Tool(description = "Add")
        public int add(int a, int b) { return a + b; }
        public Calc() {}
        private int helper(int x) { return x; }
    }
    """
    root, src_b = parse_java(src)
    matches = run_query(java_bundle.functions, root, src_b)
    names = sorted(m["func_name"][0] for m in matches)
    assert names == ["Calc", "add", "helper"]


def test_java_functions_handle_overloads(parse_java, java_bundle, run_query):
    """Two methods with the same name produce two distinct
    ``func_def`` matches — the index keeps the first one (matching
    the imperative ``setdefault`` semantics).
    """
    src = """
    public class Calc {
        public int add(int a, int b) { return a + b; }
        public double add(double a, double b) { return a + b; }
    }
    """
    root, src_b = parse_java(src)
    matches = run_query(java_bundle.functions, root, src_b)
    assert [m["func_name"][0] for m in matches] == ["add", "add"]


# ----------------------------------------------------------------------
# C#: ``[McpServerTool]`` attributes. ``local_function_statement`` is
# included for parity with ``FUNCTION_NODE_TYPES["c_sharp"]``.
# ----------------------------------------------------------------------


def test_csharp_functions_capture_methods_constructors_and_locals(
    parse_csharp, csharp_bundle, run_query
):
    src = """
    [McpServerToolType]
    public class Calc {
        [McpServerTool]
        public int Add(int a, int b) => a + b;

        public Calc() {}

        public void Outer() {
            int Local(int n) => n;
            Local(1);
        }
    }
    """
    root, src_b = parse_csharp(src)
    matches = run_query(csharp_bundle.functions, root, src_b)
    names = sorted(m["func_name"][0] for m in matches)
    assert names == ["Add", "Calc", "Local", "Outer"]


# ----------------------------------------------------------------------
# Rust: ``#[tool]`` attribute macros. Attributes are SIBLINGS of the
# function_item, not children — the annotation collector handles the
# sibling navigation, the query just enumerates function declarations.
# ----------------------------------------------------------------------


def test_rust_functions_capture_free_and_impl_methods(
    parse_rust, rust_bundle, run_query
):
    src = """
    fn helper(x: i32) -> i32 { x }

    struct Calc;

    impl Calc {
        #[tool]
        fn add(&self, a: i32, b: i32) -> i32 { a + b }

        fn private_helper(&self) -> i32 { 0 }
    }
    """
    root, src_b = parse_rust(src)
    matches = run_query(rust_bundle.functions, root, src_b)
    names = sorted(m["func_name"][0] for m in matches)
    assert names == ["add", "helper", "private_helper"]


def test_rust_functions_skip_impl_item_itself(
    parse_rust, rust_bundle, run_query
):
    """``impl_item`` is in ``FUNCTION_NODE_TYPES["rust"]`` for
    historical reasons but excluded by ``_TS_NON_FUNCTION_NODE_TYPES``;
    the query mirrors that — only ``function_item`` is captured."""
    src = """
    impl SomeTrait for SomeStruct {
        fn method(&self) {}
    }
    """
    root, src_b = parse_rust(src)
    matches = run_query(rust_bundle.functions, root, src_b)
    # Only the inner ``function_item`` — never the ``impl_item``.
    assert [m["func_name"][0] for m in matches] == ["method"]


# ----------------------------------------------------------------------
# PHP: ``#[McpTool(...)]`` attributes (PHP 8 attribute syntax). Both
# free functions and class methods are captured.
# ----------------------------------------------------------------------


def test_php_functions_capture_free_and_methods(
    parse_php, php_bundle, run_query
):
    src = """<?php
    function helper(float $x): float { return $x; }
    class Calc {
        private function priv(int $n): int { return $n; }

        #[McpTool(name: "add", description: "Add")]
        public function add(int $a, int $b): int { return $a + $b; }
    }
    """
    root, src_b = parse_php(src)
    matches = run_query(php_bundle.functions, root, src_b)
    names = sorted(m["func_name"][0] for m in matches)
    assert names == ["add", "helper", "priv"]


# ----------------------------------------------------------------------
# Ruby: ``# @tool`` leading comments. Both ``method`` and
# ``singleton_method`` (``def self.foo``) are captured.
# ----------------------------------------------------------------------


def test_ruby_functions_capture_method_and_singleton_method(
    parse_ruby, ruby_bundle, run_query
):
    src = """
    def helper(x); x; end

    # @tool name: "add"
    def add(a, b); helper(a) + b; end

    class C
      def self.singleton_one; end
      def regular; end
    end
    """
    root, src_b = parse_ruby(src)
    matches = run_query(ruby_bundle.functions, root, src_b)
    names = sorted(m["func_name"][0] for m in matches)
    assert names == ["add", "helper", "regular", "singleton_one"]
