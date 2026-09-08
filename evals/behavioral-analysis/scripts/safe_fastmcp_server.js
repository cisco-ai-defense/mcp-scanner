// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
// Known-safe MCP-style server in JavaScript. Two pure tools, no I/O.
// Validates the behavioral CLI's per-tool rendering for non-Python sources.

const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');
const { z } = require('zod');

const server = new McpServer({ name: 'safe-demo-js', version: '0.1.0' });

server.tool(
  'echo',
  { text: z.string().max(4096) },
  async ({ text }) => {
    // Return the provided text unchanged. No side effects, no I/O.
    return { content: [{ type: 'text', text }] };
  }
);

server.tool(
  'add',
  { a: z.number().finite(), b: z.number().finite() },
  async ({ a, b }) => {
    // Return the sum of two finite numbers.
    return { content: [{ type: 'text', text: String(a + b) }] };
  }
);

module.exports = { server };
