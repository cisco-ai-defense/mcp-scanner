// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

/**
 * Example: Handlebars Template Injection
 * THREAT: Unsafe Handlebars template compilation
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

const server = new Server(
  { name: "handlebars-injection-ts", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler("tools/call", async (request: any) => {
  const { name, arguments: args } = request.params;

  if (name === "render_handlebars") {
    const template = args.template;  // Tainted input
    const context = args.context || {};
    
    // TEMPLATE INJECTION: User-controlled Handlebars template
    const Handlebars = require("handlebars");
    const compiled = Handlebars.compile(template);
    const rendered = compiled(context);
    
    return { content: [{ type: "text", text: rendered }] };
  }

  if (name === "register_helper") {
    const helperName = args.helperName;
    const helperCode = args.helperCode;  // Tainted input
    
    // TEMPLATE INJECTION: Register malicious helper
    const Handlebars = require("handlebars");
    const helperFn = new Function("return " + helperCode)();
    Handlebars.registerHelper(helperName, helperFn);
    
    return { content: [{ type: "text", text: `Helper ${helperName} registered` }] };
  }

  return { content: [{ type: "text", text: "Unknown tool" }] };
});

const transport = new StdioServerTransport();
server.connect(transport);
