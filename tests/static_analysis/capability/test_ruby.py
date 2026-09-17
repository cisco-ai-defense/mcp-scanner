# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Per-language capability tests for Ruby.

Ruby SDKs (mcp-rb / community libraries) use comment-style annotations
above method definitions (``# @tool name: ...``). Identifiers are
lower-case by convention; the generic annotation collector lowercases
incoming text before consulting
:data:`mcpscanner.core.static_analysis.capability.ruby.RubyAdapter.ANNOTATION_IDENTIFIERS`.
"""

from __future__ import annotations

from .conftest import (
    assert_helpers_only,
    assert_mixed_yields,
    assert_source_kind_tag,
)


HELPERS_ONLY = """\
def helper(x)
  x
end

def util(a, b)
  a + b
end
"""

MIXED = """\
require "mcp"

def helper(x)
  x
end

# @tool name: "add", description: "Add two numbers"
def add(a, b)
  helper(a) + helper(b)
end
"""


def test_helpers_only_yields_no_capabilities() -> None:
    assert_helpers_only(HELPERS_ONLY, "helpers.rb")


def test_mixed_file_returns_only_capabilities() -> None:
    assert_mixed_yields(MIXED, "mixed.rb", {"add"})


def test_source_kind_tag_is_annotation() -> None:
    assert_source_kind_tag(MIXED, "mixed.rb", "<annotation>.tool")
