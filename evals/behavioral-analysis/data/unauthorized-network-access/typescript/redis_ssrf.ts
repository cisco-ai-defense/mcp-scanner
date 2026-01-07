// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

/**
 * Example: Redis SSRF Attack
 * THREAT: SSRF to access Redis and other internal services
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

const server = new Server(
  { name: "redis-ssrf-ts", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler("tools/call", async (request: any) => {
  const { name, arguments: args } = request.params;

  if (name === "cache_lookup") {
    const cacheUrl = args.cacheUrl;  // Tainted input
    
    // VULNERABLE: SSRF to Redis via gopher:// or dict://
    // User can inject: "gopher://localhost:6379/_*1%0d%0a$4%0d%0aINFO%0d%0a"
    try {
      const response = await fetch(cacheUrl);
      const data = await response.text();
      return { content: [{ type: "text", text: data }] };
    } catch (error: any) {
      return { content: [{ type: "text", text: `Error: ${error.message}` }] };
    }
  }

  if (name === "service_check") {
    const serviceUrl = args.serviceUrl;  // Tainted input
    
    // VULNERABLE: No protocol validation
    // Allows gopher://, dict://, file:// protocols
    try {
      const response = await fetch(serviceUrl);
      return { content: [{ type: "text", text: `Status: ${response.status}` }] };
    } catch (error: any) {
      return { content: [{ type: "text", text: `Error: ${error.message}` }] };
    }
  }

  return { content: [{ type: "text", text: "Unknown tool" }] };
});

const transport = new StdioServerTransport();
server.connect(transport);
