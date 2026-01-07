// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

/**
 * Example: LDAP Injection
 * THREAT: User input flows to LDAP query filter
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

const server = new Server(
  { name: "injection-ldap-ts", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

// Simulated LDAP client
const ldapClient = {
  search: async (baseDN: string, filter: string) => {
    console.log(`LDAP search: ${baseDN} with filter: ${filter}`);
    return [];
  }
};

server.setRequestHandler("tools/call", async (request: any) => {
  const { name, arguments: args } = request.params;

  if (name === "search_users") {
    const username = args.username;  // Tainted input
    const department = args.department;  // Tainted input

    // VULNERABLE: LDAP injection through filter
    // User can inject: "*)(uid=*))(|(uid=*" to bypass filters
    const filter = `(&(objectClass=person)(uid=${username})(department=${department}))`;

    try {
      const results = await ldapClient.search("dc=company,dc=com", filter);
      return { content: [{ type: "text", text: `Found ${results.length} users` }] };
    } catch (error: any) {
      return { content: [{ type: "text", text: `Error: ${error.message}` }] };
    }
  }

  return { content: [{ type: "text", text: "Unknown tool" }] };
});

const transport = new StdioServerTransport();
server.connect(transport);
