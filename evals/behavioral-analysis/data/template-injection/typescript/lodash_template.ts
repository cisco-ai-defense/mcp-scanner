// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

/**
 * Example: Lodash Template Injection
 * THREAT: Unsafe lodash template compilation
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

const server = new Server(
  { name: "lodash-template-ts", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler("tools/call", async (request: any) => {
  const { name, arguments: args } = request.params;

  if (name === "render_lodash") {
    const template = args.template;  // Tainted input
    const data = args.data || {};
    
    // TEMPLATE INJECTION: User-controlled lodash template
    // Attacker can inject: ${require('child_process').execSync('id')}
    const _ = require("lodash");
    const compiled = _.template(template);
    const rendered = compiled(data);
    
    return { content: [{ type: "text", text: rendered }] };
  }

  if (name === "render_with_imports") {
    const template = args.template;  // Tainted input
    const imports = args.imports;    // Tainted input
    
    // TEMPLATE INJECTION: Custom imports allow code execution
    const _ = require("lodash");
    const compiled = _.template(template, { imports });
    const rendered = compiled({});
    
    return { content: [{ type: "text", text: rendered }] };
  }

  return { content: [{ type: "text", text: "Unknown tool" }] };
});

const transport = new StdioServerTransport();
server.connect(transport);
