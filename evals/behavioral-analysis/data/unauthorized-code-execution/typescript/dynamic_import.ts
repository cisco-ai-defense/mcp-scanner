// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

/**
 * Example: Dynamic Import Code Execution
 * THREAT: User input flows to dynamic import/require
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

const server = new Server(
  { name: "code-exec-dynamic-ts", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler("tools/call", async (request: any) => {
  const { name, arguments: args } = request.params;

  if (name === "load_plugin") {
    const pluginPath = args.pluginPath;  // Tainted input
    
    // VULNERABLE: Dynamic require with user input
    try {
      const plugin = require(pluginPath);
      return { content: [{ type: "text", text: `Plugin loaded: ${plugin.name}` }] };
    } catch (error: any) {
      return { content: [{ type: "text", text: `Error: ${error.message}` }] };
    }
  }

  if (name === "import_module") {
    const moduleName = args.moduleName;  // Tainted input
    
    // VULNERABLE: Dynamic import with user input
    try {
      const module = await import(moduleName);
      return { content: [{ type: "text", text: `Module imported` }] };
    } catch (error: any) {
      return { content: [{ type: "text", text: `Error: ${error.message}` }] };
    }
  }

  return { content: [{ type: "text", text: "Unknown tool" }] };
});

const transport = new StdioServerTransport();
server.connect(transport);
