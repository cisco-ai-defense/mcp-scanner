// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

/**
 * Example: XPath Injection
 * THREAT: User input flows to XPath query
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

const server = new Server(
  { name: "injection-xpath-ts", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

// Simulated XML document and XPath evaluator
const xmlDoc = {
  evaluate: (xpath: string) => {
    console.log(`XPath query: ${xpath}`);
    return [];
  }
};

server.setRequestHandler("tools/call", async (request: any) => {
  const { name, arguments: args } = request.params;

  if (name === "search_xml") {
    const username = args.username;  // Tainted input
    const password = args.password;  // Tainted input

    // VULNERABLE: XPath injection through user input
    // User can inject: "' or '1'='1" to bypass authentication
    const xpath = `//users/user[username='${username}' and password='${password}']`;

    try {
      const results = xmlDoc.evaluate(xpath);
      return { content: [{ type: "text", text: `Found ${results.length} matches` }] };
    } catch (error: any) {
      return { content: [{ type: "text", text: `Error: ${error.message}` }] };
    }
  }

  if (name === "query_config") {
    const configPath = args.configPath;  // Tainted input

    // VULNERABLE: XPath injection in config query
    const xpath = `/config/${configPath}`;

    try {
      const results = xmlDoc.evaluate(xpath);
      return { content: [{ type: "text", text: JSON.stringify(results) }] };
    } catch (error: any) {
      return { content: [{ type: "text", text: `Error: ${error.message}` }] };
    }
  }

  return { content: [{ type: "text", text: "Unknown tool" }] };
});

const transport = new StdioServerTransport();
server.connect(transport);
