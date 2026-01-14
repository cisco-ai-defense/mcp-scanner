// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

/**
 * Example: new Function() Code Execution
 * THREAT: User input flows to Function constructor
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

const server = new Server(
  { name: "code-exec-function-ts", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler("tools/call", async (request: any) => {
  const { name, arguments: args } = request.params;

  if (name === "execute_expression") {
    const expression = args.expression;  // Tainted input
    
    // VULNERABLE: Function constructor with user input
    try {
      const fn = new Function(`return ${expression}`);
      const result = fn();
      return { content: [{ type: "text", text: `Result: ${result}` }] };
    } catch (error: any) {
      return { content: [{ type: "text", text: `Error: ${error.message}` }] };
    }
  }

  if (name === "create_handler") {
    const handlerCode = args.handlerCode;  // Tainted input
    const params = args.params || [];
    
    // VULNERABLE: Function constructor with user-provided code
    try {
      const handler = new Function(...params, handlerCode);
      return { content: [{ type: "text", text: "Handler created" }] };
    } catch (error: any) {
      return { content: [{ type: "text", text: `Error: ${error.message}` }] };
    }
  }

  return { content: [{ type: "text", text: "Unknown tool" }] };
});

const transport = new StdioServerTransport();
server.connect(transport);
