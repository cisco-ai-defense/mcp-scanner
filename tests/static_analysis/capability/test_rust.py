# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Per-language capability tests for Rust.

The rmcp crate uses ``#[tool]`` / ``#[prompt]`` / ``#[resource]``
attribute macros. ``#[tool_router]`` and ``#[tool_handler]`` mark the
*router* / *dispatch* impl block (not individual handlers) and are
intentionally absent from
:data:`mcpscanner.core.static_analysis.capability.rust.RustAdapter.ANNOTATION_IDENTIFIERS`.
The walker recurses into the impl and matches per-method ``#[tool]``
macros.
"""

from __future__ import annotations

from .conftest import (
    assert_helpers_only,
    assert_mixed_yields,
    assert_source_kind_tag,
)


HELPERS_ONLY = """\
fn helper(x: f64) -> f64 { x }

fn util(a: f64, b: f64) -> f64 { a + b }
"""

MIXED = """\
use rmcp::{tool, tool_router};

#[derive(Clone)]
struct Calculator;

fn helper(x: f64) -> f64 { x }

#[tool_router]
impl Calculator {
    #[tool(description = "Add two numbers")]
    fn add(&self, a: f64, b: f64) -> f64 {
        helper(a) + helper(b)
    }
}
"""


def test_helpers_only_yields_no_capabilities() -> None:
    assert_helpers_only(HELPERS_ONLY, "helpers.rs")


def test_mixed_file_returns_only_capabilities() -> None:
    assert_mixed_yields(MIXED, "mixed.rs", {"Calculator.add"})


def test_source_kind_tag_is_annotation() -> None:
    assert_source_kind_tag(MIXED, "mixed.rs", "<annotation>.tool")
