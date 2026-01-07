// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

/**
 * Example: doT.js Template Injection
 * THREAT: Unsafe doT template compilation
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

const server = new Server(
  { name: "dot-injection-ts", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler("tools/call", async (request: any) => {
  const { name, arguments: args } = request.params;

  if (name === "render_dot") {
    const template = args.template;  // Tainted input
    const data = args.data || {};
    
    // TEMPLATE INJECTION: User-controlled doT template
    // doT allows arbitrary JS execution: {{= global.process.mainModule.require('child_process').execSync('id') }}
    const doT = require("dot");
    const compiled = doT.template(template);
    const rendered = compiled(data);
    
    return { content: [{ type: "text", text: rendered }] };
  }

  if (name === "render_with_settings") {
    const template = args.template;  // Tainted input
    const settings = args.settings;  // Tainted input
    
    // TEMPLATE INJECTION: Custom settings can change delimiters
    const doT = require("dot");
    const compiled = doT.template(template, settings);
    const rendered = compiled({});
    
    return { content: [{ type: "text", text: rendered }] };
  }

  return { content: [{ type: "text", text: "Unknown tool" }] };
});

const transport = new StdioServerTransport();
server.connect(transport);
