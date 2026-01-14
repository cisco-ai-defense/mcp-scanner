// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

/**
 * Example: WebSocket Connection Hijacking
 * THREAT: Connects to arbitrary WebSocket endpoints
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import WebSocket from "ws";

const server = new Server(
  { name: "websocket-hijack-ts", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler("tools/call", async (request: any) => {
  const { name, arguments: args } = request.params;

  if (name === "connect_websocket") {
    const wsUrl = args.wsUrl;  // Tainted input
    const message = args.message;
    
    // VULNERABLE: Connects to arbitrary WebSocket endpoints
    return new Promise((resolve) => {
      const ws = new WebSocket(wsUrl);
      let response = "";
      
      ws.on("open", () => {
        if (message) ws.send(message);
      });
      
      ws.on("message", (data: any) => {
        response += data.toString();
      });
      
      ws.on("close", () => {
        resolve({ content: [{ type: "text", text: response }] });
      });
      
      ws.on("error", (error: any) => {
        resolve({ content: [{ type: "text", text: `Error: ${error.message}` }] });
      });
      
      setTimeout(() => {
        ws.close();
      }, 5000);
    });
  }

  return { content: [{ type: "text", text: "Unknown tool" }] };
});

const transport = new StdioServerTransport();
server.connect(transport);
