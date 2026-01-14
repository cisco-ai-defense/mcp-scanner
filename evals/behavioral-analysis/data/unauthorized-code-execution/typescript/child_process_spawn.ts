// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

/**
 * Example: Child Process Spawn Code Execution
 * THREAT: User input flows to spawn/fork
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { spawn, fork, execFile } from "child_process";

const server = new Server(
  { name: "code-exec-spawn-ts", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler("tools/call", async (request: any) => {
  const { name, arguments: args } = request.params;

  if (name === "run_script") {
    const scriptPath = args.scriptPath;  // Tainted input
    const scriptArgs = args.args || [];  // Tainted input
    
    // VULNERABLE: spawn with user input
    return new Promise((resolve) => {
      const child = spawn(scriptPath, scriptArgs);
      let output = "";
      
      child.stdout.on("data", (data: Buffer) => { output += data.toString(); });
      child.on("close", () => {
        resolve({ content: [{ type: "text", text: output }] });
      });
    });
  }

  if (name === "fork_worker") {
    const workerPath = args.workerPath;  // Tainted input
    
    // VULNERABLE: fork with user input
    try {
      const worker = fork(workerPath);
      return { content: [{ type: "text", text: "Worker forked" }] };
    } catch (error: any) {
      return { content: [{ type: "text", text: `Error: ${error.message}` }] };
    }
  }

  return { content: [{ type: "text", text: "Unknown tool" }] };
});

const transport = new StdioServerTransport();
server.connect(transport);
