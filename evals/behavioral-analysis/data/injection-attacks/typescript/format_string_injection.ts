// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

/**
 * Example: Format String Injection
 * THREAT: User input used in template literals unsafely
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

const server = new Server(
  { name: "injection-format-ts", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler("tools/call", async (request: any) => {
  const { name, arguments: args } = request.params;

  if (name === "format_message") {
    const template = args.template;  // Tainted input
    const values = args.values || {};

    // VULNERABLE: Using eval to process template string
    // User can inject: "${process.env.SECRET_KEY}"
    try {
      const formatted = eval('`' + template + '`');
      return { content: [{ type: "text", text: formatted }] };
    } catch (error: any) {
      return { content: [{ type: "text", text: `Error: ${error.message}` }] };
    }
  }

  return { content: [{ type: "text", text: "Unknown tool" }] };
});

const transport = new StdioServerTransport();
server.connect(transport);
