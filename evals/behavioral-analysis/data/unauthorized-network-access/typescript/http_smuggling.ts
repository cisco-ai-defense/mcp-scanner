// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

/**
 * Example: HTTP Request Smuggling
 * THREAT: Allows HTTP request smuggling attacks
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import * as http from "http";

const server = new Server(
  { name: "http-smuggling-ts", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler("tools/call", async (request: any) => {
  const { name, arguments: args } = request.params;

  if (name === "send_raw_request") {
    const host = args.host;        // Tainted input
    const port = args.port || 80;  // Tainted input
    const rawRequest = args.rawRequest;  // Tainted input
    
    // VULNERABLE: Sends raw HTTP request without validation
    // Allows HTTP smuggling via Content-Length/Transfer-Encoding conflicts
    return new Promise((resolve) => {
      const socket = require("net").createConnection({ host, port }, () => {
        socket.write(rawRequest);
      });
      
      let response = "";
      socket.on("data", (data: Buffer) => {
        response += data.toString();
      });
      
      socket.on("end", () => {
        resolve({ content: [{ type: "text", text: response }] });
      });
      
      socket.on("error", (error: any) => {
        resolve({ content: [{ type: "text", text: `Error: ${error.message}` }] });
      });
    });
  }

  return { content: [{ type: "text", text: "Unknown tool" }] };
});

const transport = new StdioServerTransport();
server.connect(transport);
