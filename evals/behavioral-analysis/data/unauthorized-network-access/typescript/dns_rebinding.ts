// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

/**
 * Example: DNS Rebinding Attack
 * THREAT: Allows DNS rebinding to access internal services
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

const server = new Server(
  { name: "dns-rebinding-ts", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler("tools/call", async (request: any) => {
  const { name, arguments: args } = request.params;

  if (name === "fetch_resource") {
    const url = args.url;  // Tainted input
    
    // VULNERABLE: No DNS rebinding protection
    // Attacker can use DNS rebinding to access internal services
    try {
      const response = await fetch(url);
      const data = await response.text();
      return { content: [{ type: "text", text: data.substring(0, 5000) }] };
    } catch (error: any) {
      return { content: [{ type: "text", text: `Error: ${error.message}` }] };
    }
  }

  if (name === "poll_endpoint") {
    const endpoint = args.endpoint;  // Tainted input
    const interval = args.interval || 5000;
    
    // VULNERABLE: Repeated requests without DNS validation
    // DNS can change between requests (rebinding)
    const results: string[] = [];
    for (let i = 0; i < 3; i++) {
      try {
        const response = await fetch(endpoint);
        results.push(await response.text());
        await new Promise(r => setTimeout(r, interval));
      } catch {}
    }
    
    return { content: [{ type: "text", text: results.join("\n---\n") }] };
  }

  return { content: [{ type: "text", text: "Unknown tool" }] };
});

const transport = new StdioServerTransport();
server.connect(transport);
