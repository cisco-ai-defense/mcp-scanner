// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

/**
 * Example: VM Sandbox Escape
 * THREAT: User input allows VM sandbox escape
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import * as vm from "vm";

const server = new Server(
  { name: "code-exec-vm-ts", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler("tools/call", async (request: any) => {
  const { name, arguments: args } = request.params;

  if (name === "run_sandbox") {
    const code = args.code;  // Tainted input
    const context = args.context || {};
    
    // VULNERABLE: vm.runInNewContext can be escaped
    // User can inject: "this.constructor.constructor('return process')().exit()"
    try {
      const result = vm.runInNewContext(code, context, { timeout: 5000 });
      return { content: [{ type: "text", text: `Result: ${JSON.stringify(result)}` }] };
    } catch (error: any) {
      return { content: [{ type: "text", text: `Error: ${error.message}` }] };
    }
  }

  if (name === "compile_script") {
    const scriptCode = args.scriptCode;  // Tainted input
    
    // VULNERABLE: vm.Script with user input
    try {
      const script = new vm.Script(scriptCode);
      const result = script.runInNewContext({});
      return { content: [{ type: "text", text: `Result: ${result}` }] };
    } catch (error: any) {
      return { content: [{ type: "text", text: `Error: ${error.message}` }] };
    }
  }

  return { content: [{ type: "text", text: "Unknown tool" }] };
});

const transport = new StdioServerTransport();
server.connect(transport);
