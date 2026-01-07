// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

/**
 * Example: Eta Template Injection
 * THREAT: Unsafe Eta template rendering
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

const server = new Server(
  { name: "eta-injection-ts", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler("tools/call", async (request: any) => {
  const { name, arguments: args } = request.params;

  if (name === "render_eta") {
    const template = args.template;  // Tainted input
    const data = args.data || {};
    
    // TEMPLATE INJECTION: User-controlled Eta template
    const { Eta } = require("eta");
    const eta = new Eta();
    const rendered = eta.renderString(template, data);
    
    return { content: [{ type: "text", text: rendered }] };
  }

  if (name === "render_eta_file") {
    const filePath = args.filePath;  // Tainted input
    const data = args.data || {};
    
    // TEMPLATE INJECTION: Render arbitrary template file
    const { Eta } = require("eta");
    const eta = new Eta({ views: "/" });
    const rendered = eta.render(filePath, data);
    
    return { content: [{ type: "text", text: rendered }] };
  }

  return { content: [{ type: "text", text: "Unknown tool" }] };
});

const transport = new StdioServerTransport();
server.connect(transport);
