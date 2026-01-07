// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

/**
 * Example: Mustache Template Injection
 * THREAT: Unsafe Mustache template rendering with custom delimiters
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

const server = new Server(
  { name: "mustache-injection-ts", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler("tools/call", async (request: any) => {
  const { name, arguments: args } = request.params;

  if (name === "render_mustache") {
    const template = args.template;  // Tainted input
    const view = args.view || {};
    
    // TEMPLATE INJECTION: User-controlled Mustache template
    const Mustache = require("mustache");
    const rendered = Mustache.render(template, view);
    
    return { content: [{ type: "text", text: rendered }] };
  }

  if (name === "render_with_partials") {
    const template = args.template;  // Tainted input
    const partials = args.partials;  // Tainted input
    const view = args.view || {};
    
    // TEMPLATE INJECTION: User-controlled partials
    const Mustache = require("mustache");
    const rendered = Mustache.render(template, view, partials);
    
    return { content: [{ type: "text", text: rendered }] };
  }

  return { content: [{ type: "text", text: "Unknown tool" }] };
});

const transport = new StdioServerTransport();
server.connect(transport);
