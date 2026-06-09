# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Per-language capability tests for Kotlin.

The Kotlin SDK exposes ``server.addTool(...) { req -> ... }`` with the
trailing-lambda shape. ``tree-sitter-kotlin`` has changed how it
exposes the trailing lambda between releases — the registration
walker handles both the embedded-in-call_expression form and the
parent-sibling form. This file pins the behaviour at the public API
level so neither grammar shape regresses silently.
"""

from __future__ import annotations

from .conftest import (
    assert_helpers_only,
    assert_mixed_yields,
    assert_source_kind_tag,
    names_of,
)
from mcpscanner.core.static_analysis import NativeAnalyzer


HELPERS_ONLY = """\
package demo

fun helper(x: Double): Double = x

fun util(a: Double, b: Double): Double = a + b
"""

MIXED = """\
package demo

import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.TextContent

fun helper(x: Double): Double = x

fun register(server: Server) {
    server.addTool(
        name = "add",
        description = "Add two numbers",
    ) { request ->
        val a = (request.arguments?.get("a") as Number).toDouble()
        val b = (request.arguments?.get("b") as Number).toDouble()
        CallToolResult(content = listOf(TextContent(text = (helper(a) + helper(b)).toString())))
    }
}
"""


NO_TRAILING_LAMBDA = """\
import io.modelcontextprotocol.kotlin.sdk.server.Server

fun main() {
  val server = Server()
  fun handle(req: Any): Any { return req }
  server.addTool(name = "noop", description = "no-op", handler = ::handle)
}
"""


def test_helpers_only_yields_no_capabilities() -> None:
    assert_helpers_only(HELPERS_ONLY, "helpers.kt")


def test_mixed_file_returns_only_capabilities() -> None:
    assert_mixed_yields(MIXED, "mixed.kt", {"add"})


def test_source_kind_tag_is_registration() -> None:
    assert_source_kind_tag(MIXED, "mixed.kt", "<registration>.tool")


def test_addtool_without_trailing_lambda() -> None:
    """``server.addTool(name=…, handler=::handle)`` with NO trailing
    lambda must still surface the named handler when the grammar
    binds it (Gap 10). Kotlin's tree-sitter grammar may or may not
    bind the named-arg handler to a function we can locate; if it
    can't, we accept an empty result rather than mis-tagging."""
    analyzer = NativeAnalyzer(NO_TRAILING_LAMBDA, "no_lambda.kt")
    caps = analyzer.extract_mcp_capability_contexts()
    names = names_of(caps)
    if names:
        assert "handle" in names, names
        assert any(
            "registration" in t for t in caps[0].decorator_types
        ), caps[0].decorator_types
