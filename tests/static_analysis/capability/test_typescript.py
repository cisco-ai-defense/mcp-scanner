# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Per-language capability tests for TypeScript.

The TS adapter at
:mod:`mcpscanner.core.static_analysis.capability.typescript` shares
its import-grammar parser with JavaScript via
:mod:`...capability._ts_imports` (composition over inheritance) but
ships its own grammar factory because tree-sitter-typescript exposes
``language_typescript()`` rather than the generic ``language()``.
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
function _validate(v: number): number { return v; }
function _coerce(v: unknown): number { return Number(v); }
export function format(label: string, value: unknown): string { return `${label}=${value}`; }
"""

MIXED = """\
import { McpServer } from '@modelcontextprotocol/server';
import * as z from 'zod/v4';

const server = new McpServer({ name: 'demo', version: '1.0.0' });

function _validate(v: number): number { return v; }

server.registerTool(
  'add',
  {
    description: 'Add two numbers',
    inputSchema: z.object({ a: z.number(), b: z.number() }),
  },
  async ({ a, b }: { a: number; b: number }) => ({
    content: [{ type: 'text', text: String(a + b) }],
  }),
);
"""


LOWLEVEL_SETREQUESTHANDLER = """\
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

const server = new Server({ name: "demo", version: "1.0" }, { capabilities: {} });

async function callToolHandler(request) {
  return { content: [{ type: "text", text: "ok" }] };
}

async function listToolsHandler() {
  return { tools: [] };
}

server.setRequestHandler(CallToolRequestSchema, callToolHandler);
server.setRequestHandler(ListToolsRequestSchema, listToolsHandler);
"""


RESOURCE_TEMPLATES = """\
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

const server = new McpServer({ name: "demo", version: "1.0" });

async function readUserResource(uri) {
  return { contents: [{ uri, text: "user data" }] };
}

server.registerResourceTemplate(
  "user-template",
  { uriTemplate: "users://{id}" },
  readUserResource
);
"""


MULTI_CAPABILITY = """\
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

const server = new McpServer({ name: "demo", version: "1.0" });

async function shared(args) {
  return { content: [{ type: "text", text: String(args) }] };
}

server.registerTool("x", { description: "x as tool" }, shared);
server.registerPrompt("x", { description: "x as prompt" }, shared);
"""


def test_helpers_only_yields_no_capabilities() -> None:
    assert_helpers_only(HELPERS_ONLY, "helpers.ts")


def test_mixed_file_returns_only_capabilities() -> None:
    assert_mixed_yields(MIXED, "mixed.ts", {"add"})


def test_source_kind_tag_is_registration() -> None:
    assert_source_kind_tag(MIXED, "mixed.ts", "<registration>.tool")


def test_lowlevel_setrequesthandler_classifies_as_tool() -> None:
    """TS low-level ``Server.setRequestHandler(CallToolRequestSchema, …)``
    must surface as a tool capability (Gap 1)."""
    analyzer = NativeAnalyzer(LOWLEVEL_SETREQUESTHANDLER, "lowlevel.ts")
    names = names_of(analyzer.extract_mcp_capability_contexts())
    assert "callToolHandler" in names, names
    assert "listToolsHandler" in names, names


def test_resource_template_classifies_as_resource_with_template_tag() -> None:
    """``registerResourceTemplate(...)`` must surface as a resource and
    carry the ``<registration.template>.resource`` tag (Gap 11)."""
    analyzer = NativeAnalyzer(RESOURCE_TEMPLATES, "templates.ts")
    caps = analyzer.extract_mcp_capability_contexts()
    assert len(caps) == 1, [c.name for c in caps]
    handler = caps[0]
    assert "readUserResource" in handler.name, handler.name
    assert "user-template" in handler.name, handler.name
    assert any(
        "registration.template" in t and t.endswith("resource")
        for t in handler.decorator_types
    ), handler.decorator_types


def test_multi_capability_yields_one_context_per_kind() -> None:
    """A single function registered as both a tool AND a prompt must
    yield two capability contexts — one tagged ``tool``, one tagged
    ``prompt`` (Gap 9)."""
    analyzer = NativeAnalyzer(MULTI_CAPABILITY, "multi.ts")
    caps = analyzer.extract_mcp_capability_contexts()
    capability_kinds = sorted(
        {
            t.split(".", 2)[1]
            for c in caps
            for t in c.decorator_types
            if t.startswith("<registration>.")
        }
    )
    assert capability_kinds == ["prompt", "tool"], capability_kinds
    assert all("shared" in c.name for c in caps), [c.name for c in caps]
    assert len(caps) == 2, len(caps)
