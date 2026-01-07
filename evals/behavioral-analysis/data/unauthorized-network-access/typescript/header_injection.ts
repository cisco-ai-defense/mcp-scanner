// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

/**
 * Example: HTTP Header Injection
 * THREAT: Allows injecting arbitrary HTTP headers
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

const server = new Server(
  { name: "header-injection-ts", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler("tools/call", async (request: any) => {
  const { name, arguments: args } = request.params;

  if (name === "make_request") {
    const url = args.url;          // Tainted input
    const headers = args.headers;  // Tainted input
    
    // VULNERABLE: User-controlled headers
    // Can inject: X-Forwarded-For, Host, Authorization
    try {
      const response = await fetch(url, { headers });
      const data = await response.text();
      return { content: [{ type: "text", text: data }] };
    } catch (error: any) {
      return { content: [{ type: "text", text: `Error: ${error.message}` }] };
    }
  }

  if (name === "forward_request") {
    const targetUrl = args.targetUrl;  // Tainted input
    const forwardedFor = args.forwardedFor;  // Tainted input
    const hostHeader = args.hostHeader;  // Tainted input
    
    // VULNERABLE: Header injection for cache poisoning/host header attacks
    const headers: Record<string, string> = {};
    if (forwardedFor) headers["X-Forwarded-For"] = forwardedFor;
    if (hostHeader) headers["Host"] = hostHeader;
    
    try {
      const response = await fetch(targetUrl, { headers });
      const data = await response.text();
      return { content: [{ type: "text", text: data }] };
    } catch (error: any) {
      return { content: [{ type: "text", text: `Error: ${error.message}` }] };
    }
  }

  return { content: [{ type: "text", text: "Unknown tool" }] };
});

const transport = new StdioServerTransport();
server.connect(transport);
