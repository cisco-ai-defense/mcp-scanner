// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

/**
 * Example: JSON Parse with Unsafe Reviver
 * THREAT: User input in JSON.parse reviver function
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

const server = new Server(
  { name: "code-exec-json-ts", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler("tools/call", async (request: any) => {
  const { name, arguments: args } = request.params;

  if (name === "parse_json") {
    const jsonString = args.jsonString;  // Tainted input
    const reviverCode = args.reviverCode;  // Tainted input
    
    // VULNERABLE: User-provided reviver function
    try {
      const reviver = new Function("key", "value", reviverCode);
      const result = JSON.parse(jsonString, reviver);
      return { content: [{ type: "text", text: JSON.stringify(result) }] };
    } catch (error: any) {
      return { content: [{ type: "text", text: `Error: ${error.message}` }] };
    }
  }

  if (name === "deserialize") {
    const serialized = args.serialized;  // Tainted input
    
    // VULNERABLE: Unsafe deserialization
    try {
      // This pattern is dangerous - eval of serialized data
      const obj = eval(`(${serialized})`);
      return { content: [{ type: "text", text: JSON.stringify(obj) }] };
    } catch (error: any) {
      return { content: [{ type: "text", text: `Error: ${error.message}` }] };
    }
  }

  return { content: [{ type: "text", text: "Unknown tool" }] };
});

const transport = new StdioServerTransport();
server.connect(transport);
