# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Per-language capability tests for Go.

The Go SDK uses a top-level ``mcp.AddTool(server, &mcp.Tool{...},
handler)`` shape where the *first* argument is the server instance —
not the receiver. The adapter
(:mod:`mcpscanner.core.static_analysis.capability.go`) overrides
:py:meth:`parse_import_alias` to capture the package alias the user
imported the SDK as (``import "github.com/...mcp"`` exposes ``mcp``;
``import alias "..."`` rebinds it).
"""

from __future__ import annotations

from .conftest import (
    assert_helpers_only,
    assert_mixed_yields,
    assert_source_kind_tag,
)


HELPERS_ONLY = """\
package main

func validate(x float64) error { return nil }

func helper(a, b float64) float64 { return a + b }

func main() {}
"""

MIXED = """\
package main

import (
    "context"
    "github.com/modelcontextprotocol/go-sdk/mcp"
)

type AddInput struct {
    A float64 `json:"a"`
    B float64 `json:"b"`
}

type AddOutput struct {
    Sum float64 `json:"sum"`
}

func validate(x float64) error { return nil }

func add(ctx context.Context, req *mcp.CallToolRequest, in AddInput) (*mcp.CallToolResult, AddOutput, error) {
    return nil, AddOutput{Sum: in.A + in.B}, nil
}

func main() {
    server := mcp.NewServer(&mcp.Implementation{Name: "demo", Version: "v1.0.0"}, nil)
    mcp.AddTool(server, &mcp.Tool{Name: "add", Description: "Add two numbers"}, add)
}
"""


def test_helpers_only_yields_no_capabilities() -> None:
    assert_helpers_only(HELPERS_ONLY, "helpers.go")


def test_mixed_file_returns_only_capabilities() -> None:
    assert_mixed_yields(MIXED, "mixed.go", {"add"})


def test_source_kind_tag_is_registration() -> None:
    assert_source_kind_tag(MIXED, "mixed.go", "<registration>.tool")
