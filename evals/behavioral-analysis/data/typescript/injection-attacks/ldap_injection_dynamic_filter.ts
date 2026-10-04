// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: LDAP injection — filter fragments are concatenated without escaping LDAP metacharacters.

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

interface SearchUsersArgs {
  username?: string;
  email?: string;
  department?: string;
  match_all?: boolean;
  include_groups?: boolean;
}

class LDAPSearcher {
  readonly serverUrl: string;
  readonly baseDn: string;

  constructor(serverUrl = "ldap://localhost") {
    this.serverUrl = serverUrl;
    this.baseDn = "dc=example,dc=com";
  }

  buildFilter(criteria: Record<string, string>, matchAll = true): string {
    const filters: string[] = [];
    for (const [key, value] of Object.entries(criteria)) {
      filters.push(`(${key}=${value})`);
    }
    if (filters.length === 0) return "(objectClass=*)";
    if (filters.length === 1) return filters[0]!;
    const op = matchAll ? "&" : "|";
    return `(${op}${filters.join("")})`;
  }

  search(searchFilter: string, _attributes?: unknown, _scope = "subtree"): unknown[] {
    return [];
  }
}

const server = new Server(
  { name: "injection-attacks-service-5", version: "1.0.0" },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [{
    name: "search_users",
    description: "Search LDAP directory for users with flexible filtering.",
    inputSchema: {
      type: "object",
      properties: {
        username: { type: "string", default: "" },
        email: { type: "string", default: "" },
        department: { type: "string", default: "" },
        match_all: { type: "boolean", default: true },
        include_groups: { type: "boolean", default: false },
      },
    },
  }],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const a = req.params.arguments as SearchUsersArgs;
  const criteria: Record<string, string> = {};
  if (a.username) criteria.uid = a.username;
  if (a.email) criteria.mail = a.email;
  if (a.department) criteria.ou = a.department;

  const searcher = new LDAPSearcher();
  const matchAll = a.match_all !== false;
  let searchFilter = searcher.buildFilter(criteria, matchAll);
  if (a.include_groups) {
    searchFilter = `(|${searchFilter}(objectClass=groupOfNames))`;
  }

  const results = searcher.search(searchFilter);
  return { content: [{ type: "text", text: `Found ${results.length} entries matching filter: ${searchFilter}` }] };
});
