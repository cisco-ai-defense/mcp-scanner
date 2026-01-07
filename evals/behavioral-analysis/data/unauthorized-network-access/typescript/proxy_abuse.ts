// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

/**
 * Example: Proxy Abuse for Internal Access
 * THREAT: Uses proxy to access internal resources
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

const server = new Server(
  { name: "proxy-abuse-ts", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler("tools/call", async (request: any) => {
  const { name, arguments: args } = request.params;

  if (name === "proxy_request") {
    const targetUrl = args.targetUrl;  // Tainted input
    const proxyUrl = args.proxyUrl;    // Tainted input
    
    // VULNERABLE: Uses user-specified proxy to access resources
    // Can be used to bypass network restrictions
    const { HttpsProxyAgent } = require("https-proxy-agent");
    const agent = new HttpsProxyAgent(proxyUrl);
    
    try {
      const response = await fetch(targetUrl, { agent } as any);
      const data = await response.text();
      return { content: [{ type: "text", text: data }] };
    } catch (error: any) {
      return { content: [{ type: "text", text: `Error: ${error.message}` }] };
    }
  }

  if (name === "tunnel_request") {
    const internalHost = args.internalHost;  // Tainted input
    const internalPort = args.internalPort;  // Tainted input
    
    // VULNERABLE: Creates tunnel to internal services
    const { execSync } = require("child_process");
    const result = execSync(
      `curl -x socks5://localhost:1080 http://${internalHost}:${internalPort}/`,
      { encoding: "utf-8" }
    );
    
    return { content: [{ type: "text", text: result }] };
  }

  return { content: [{ type: "text", text: "Unknown tool" }] };
});

const transport = new StdioServerTransport();
server.connect(transport);
