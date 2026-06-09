# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Per-language capability tests for JavaScript.

JavaScript shares the official ``@modelcontextprotocol/sdk`` SDK with
TypeScript but gets its own adapter (``capability/javascript.py``) and
its own test file so a tree-sitter-javascript grammar regression
doesn't take TypeScript down with it. The two adapters delegate
import-grammar parsing to a shared helper module
(:mod:`mcpscanner.core.static_analysis.capability._ts_imports`) —
composition over inheritance.
"""

from __future__ import annotations

from .conftest import (
    assert_helpers_only,
    assert_mixed_yields,
    assert_source_kind_tag,
)


HELPERS_ONLY = """\
function _validate(v) { return v; }
function _coerce(v) { return Number(v); }
function format(label, value) { return label + '=' + value; }
"""

MIXED = """\
const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');
const { z } = require('zod');

const server = new McpServer({ name: 'demo', version: '0.1.0' });

function _validate(v) { return v; }
function _coerce(v) { return Number(v); }

server.tool(
  'add',
  { a: z.number(), b: z.number() },
  async ({ a, b }) => ({ content: [{ type: 'text', text: String(a + b) }] }),
);
"""


def test_helpers_only_yields_no_capabilities() -> None:
    assert_helpers_only(HELPERS_ONLY, "helpers.js")


def test_mixed_file_returns_only_capabilities() -> None:
    assert_mixed_yields(MIXED, "mixed.js", {"add"})


def test_source_kind_tag_is_registration() -> None:
    assert_source_kind_tag(MIXED, "mixed.js", "<registration>.tool")
