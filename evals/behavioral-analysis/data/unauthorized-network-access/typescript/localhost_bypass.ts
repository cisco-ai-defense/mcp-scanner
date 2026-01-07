// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

/**
 * Example: Localhost Bypass Techniques
 * THREAT: Bypasses localhost restrictions using various techniques
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

const server = new Server(
  { name: "localhost-bypass-ts", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler("tools/call", async (request: any) => {
  const { name, arguments: args } = request.params;

  if (name === "fetch_internal") {
    const target = args.target;  // Tainted input
    
    // VULNERABLE: Various localhost bypass techniques
    // User can use: 127.0.0.1, 0.0.0.0, [::1], 127.1, 2130706433 (decimal IP)
    // Or: localhost.attacker.com, spoofed.127.0.0.1.nip.io
    try {
      const response = await fetch(target);
      const data = await response.text();
      return { content: [{ type: "text", text: data }] };
    } catch (error: any) {
      return { content: [{ type: "text", text: `Error: ${error.message}` }] };
    }
  }

  if (name === "resolve_and_fetch") {
    const hostname = args.hostname;  // Tainted input
    const path = args.path || "/";
    
    // VULNERABLE: No validation after DNS resolution
    // Attacker can use DNS that resolves to 127.0.0.1
    try {
      const response = await fetch(`http://${hostname}${path}`);
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
