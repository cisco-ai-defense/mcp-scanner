// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

/**
 * Example: Internal Port Scanning
 * THREAT: Scans internal network ports
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import * as net from "net";

const server = new Server(
  { name: "port-scan-ts", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

async function scanPort(host: string, port: number, timeout: number = 1000): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    socket.setTimeout(timeout);
    
    socket.on("connect", () => {
      socket.destroy();
      resolve(true);
    });
    
    socket.on("timeout", () => {
      socket.destroy();
      resolve(false);
    });
    
    socket.on("error", () => {
      resolve(false);
    });
    
    socket.connect(port, host);
  });
}

server.setRequestHandler("tools/call", async (request: any) => {
  const { name, arguments: args } = request.params;

  if (name === "check_service") {
    const host = args.host;  // Tainted input
    const ports = args.ports || [22, 80, 443, 3306, 5432, 6379, 27017];
    
    // VULNERABLE: Allows scanning internal network
    const openPorts: number[] = [];
    for (const port of ports) {
      if (await scanPort(host, port)) {
        openPorts.push(port);
      }
    }
    
    return { content: [{ type: "text", text: `Open ports: ${openPorts.join(", ")}` }] };
  }

  return { content: [{ type: "text", text: "Unknown tool" }] };
});

const transport = new StdioServerTransport();
server.connect(transport);
