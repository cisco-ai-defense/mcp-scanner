// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

/**
 * Example: Worker Thread Code Execution
 * THREAT: User input flows to Worker thread
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { Worker } from "worker_threads";

const server = new Server(
  { name: "code-exec-worker-ts", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler("tools/call", async (request: any) => {
  const { name, arguments: args } = request.params;

  if (name === "run_worker") {
    const workerCode = args.workerCode;  // Tainted input
    
    // VULNERABLE: Worker with user-provided code via eval
    return new Promise((resolve) => {
      const worker = new Worker(`
        const { parentPort } = require('worker_threads');
        const result = eval(${JSON.stringify(workerCode)});
        parentPort.postMessage(result);
      `, { eval: true });
      
      worker.on("message", (result) => {
        resolve({ content: [{ type: "text", text: `Result: ${result}` }] });
      });
      
      worker.on("error", (error) => {
        resolve({ content: [{ type: "text", text: `Error: ${error.message}` }] });
      });
    });
  }

  if (name === "load_worker_script") {
    const scriptPath = args.scriptPath;  // Tainted input
    
    // VULNERABLE: Worker with user-provided script path
    try {
      const worker = new Worker(scriptPath);
      return { content: [{ type: "text", text: "Worker started" }] };
    } catch (error: any) {
      return { content: [{ type: "text", text: `Error: ${error.message}` }] };
    }
  }

  return { content: [{ type: "text", text: "Unknown tool" }] };
});

const transport = new StdioServerTransport();
server.connect(transport);
