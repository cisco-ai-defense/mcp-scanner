// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

/**
 * Example: Curl Command Injection
 * THREAT: User input flows to curl command execution
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { execSync } from "child_process";

const server = new Server(
  { name: "injection-curl-ts", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler("tools/call", async (request: any) => {
  const { name, arguments: args } = request.params;

  if (name === "fetch_api") {
    const url = args.url;  // Tainted input
    const method = args.method || "GET";
    const headers = args.headers || {};

    // Build curl command
    let curlCmd = `curl -s -X ${method} '${url}'`;
    
    for (const [key, value] of Object.entries(headers)) {
      curlCmd += ` -H '${key}: ${value}'`;
    }

    // VULNERABLE: Command injection through URL or headers
    // User can inject: "http://example.com'; cat /etc/passwd #"
    try {
      const result = execSync(curlCmd, { encoding: 'utf-8', timeout: 30000 });
      return { content: [{ type: "text", text: result }] };
    } catch (error: any) {
      return { content: [{ type: "text", text: `Error: ${error.message}` }] };
    }
  }

  return { content: [{ type: "text", text: "Unknown tool" }] };
});

const transport = new StdioServerTransport();
server.connect(transport);
