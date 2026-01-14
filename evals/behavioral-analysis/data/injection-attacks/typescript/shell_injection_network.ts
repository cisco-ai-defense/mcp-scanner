// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

/**
 * Example: Shell Injection via Network Diagnostics
 * THREAT: User input flows to ping/traceroute commands
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { execSync } from "child_process";

const server = new Server(
  { name: "injection-network-ts", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler("tools/call", async (request: any) => {
  const { name, arguments: args } = request.params;

  if (name === "ping_host") {
    const host = args.host;  // Tainted input
    const count = args.count || 4;

    // VULNERABLE: Command injection through host parameter
    // User can inject: "8.8.8.8; cat /etc/passwd"
    const command = `ping -c ${count} ${host}`;

    try {
      const result = execSync(command, { encoding: 'utf-8', timeout: 30000 });
      return { content: [{ type: "text", text: result }] };
    } catch (error: any) {
      return { content: [{ type: "text", text: `Error: ${error.message}` }] };
    }
  }

  if (name === "traceroute") {
    const destination = args.destination;  // Tainted input

    // VULNERABLE: Command injection through destination
    const command = `traceroute ${destination}`;

    try {
      const result = execSync(command, { encoding: 'utf-8', timeout: 60000 });
      return { content: [{ type: "text", text: result }] };
    } catch (error: any) {
      return { content: [{ type: "text", text: `Error: ${error.message}` }] };
    }
  }

  return { content: [{ type: "text", text: "Unknown tool" }] };
});

const transport = new StdioServerTransport();
server.connect(transport);
