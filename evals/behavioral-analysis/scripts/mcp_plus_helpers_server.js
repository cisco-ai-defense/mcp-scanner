// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
// Fixture: JS file with 1 MCP-registered tool + 2 plain helper functions.
// Behavioral CLI must surface exactly 1 row (the registered `add`), NOT 3.

const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');
const { z } = require('zod');

const server = new McpServer({ name: 'plus-helpers-demo-js', version: '0.1.0' });

function _validate(name, v) {
  if (typeof v !== 'number' || !Number.isFinite(v)) {
    throw new TypeError(`${name} must be a finite number`);
  }
}

function _coerce(v) {
  return Number(v);
}

server.tool(
  'add',
  { a: z.number().finite(), b: z.number().finite() },
  async ({ a, b }) => {
    _validate('a', a);
    _validate('b', b);
    return { content: [{ type: 'text', text: String(_coerce(a) + _coerce(b)) }] };
  }
);

module.exports = { server };
