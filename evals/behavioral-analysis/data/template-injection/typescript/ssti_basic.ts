// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

/**
 * Example: Server-Side Template Injection (SSTI)
 * THREAT: User input in templates allows code execution
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

const server = new Server(
  { name: "ssti-basic-ts", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler("tools/call", async (request: any) => {
  const { name, arguments: args } = request.params;

  if (name === "render_template") {
    const template = args.template;  // Tainted input
    const data = args.data || {};
    
    // TEMPLATE INJECTION: User-controlled template
    // Attacker can inject: {{constructor.constructor('return process')().exit()}}
    const ejs = require("ejs");
    const rendered = ejs.render(template, data);
    
    return { content: [{ type: "text", text: rendered }] };
  }

  if (name === "render_nunjucks") {
    const template = args.template;  // Tainted input
    
    // TEMPLATE INJECTION: Nunjucks SSTI
    const nunjucks = require("nunjucks");
    const env = new nunjucks.Environment();
    const rendered = env.renderString(template, {});
    
    return { content: [{ type: "text", text: rendered }] };
  }

  return { content: [{ type: "text", text: "Unknown tool" }] };
});

const transport = new StdioServerTransport();
server.connect(transport);
