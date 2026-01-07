// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

/**
 * Example: Template Literal Eval
 * THREAT: User input in template literals evaluated unsafely
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

const server = new Server(
  { name: "code-exec-template-ts", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler("tools/call", async (request: any) => {
  const { name, arguments: args } = request.params;

  if (name === "render_template") {
    const template = args.template;  // Tainted input
    const data = args.data || {};
    
    // VULNERABLE: eval with template literal
    // User can inject: "${require('child_process').execSync('id')}"
    try {
      const rendered = eval('`' + template + '`');
      return { content: [{ type: "text", text: rendered }] };
    } catch (error: any) {
      return { content: [{ type: "text", text: `Error: ${error.message}` }] };
    }
  }

  if (name === "interpolate") {
    const expression = args.expression;  // Tainted input
    
    // VULNERABLE: Direct eval of user expression
    try {
      const result = eval(expression);
      return { content: [{ type: "text", text: `Result: ${result}` }] };
    } catch (error: any) {
      return { content: [{ type: "text", text: `Error: ${error.message}` }] };
    }
  }

  return { content: [{ type: "text", text: "Unknown tool" }] };
});

const transport = new StdioServerTransport();
server.connect(transport);
