// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

/**
 * Example: setTimeout/setInterval String Eval
 * THREAT: User input in setTimeout/setInterval string argument
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

const server = new Server(
  { name: "code-exec-timeout-ts", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler("tools/call", async (request: any) => {
  const { name, arguments: args } = request.params;

  if (name === "schedule_task") {
    const taskCode = args.taskCode;  // Tainted input
    const delay = args.delay || 1000;
    
    // VULNERABLE: setTimeout with string argument (acts like eval)
    setTimeout(taskCode, delay);
    
    return { content: [{ type: "text", text: `Task scheduled in ${delay}ms` }] };
  }

  if (name === "start_interval") {
    const intervalCode = args.intervalCode;  // Tainted input
    const interval = args.interval || 5000;
    
    // VULNERABLE: setInterval with string argument
    const id = setInterval(intervalCode, interval);
    
    return { content: [{ type: "text", text: `Interval started: ${id}` }] };
  }

  return { content: [{ type: "text", text: "Unknown tool" }] };
});

const transport = new StdioServerTransport();
server.connect(transport);
