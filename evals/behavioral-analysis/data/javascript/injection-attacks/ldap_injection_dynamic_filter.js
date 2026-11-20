// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: LDAP injection — filter fragments are concatenated without escaping LDAP metacharacters.

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

class LDAPSearcher {
  constructor(serverUrl = "ldap://localhost") {
    this.serverUrl = serverUrl;
    this.baseDn = "dc=example,dc=com";
  }

  buildFilter(criteria, matchAll = true) {
    const filters = [];
    for (const [key, value] of Object.entries(criteria)) {
      // VULNERABLE: No escaping of special LDAP characters
      filters.push(`(${key}=${value})`);
    }
    if (filters.length === 0) return "(objectClass=*)";
    if (filters.length === 1) return filters[0];
    const op = matchAll ? "&" : "|";
    return `(${op}${filters.join("")})`;
  }

  /** Stub: mirrors Python LDAP call without binding real ldap3. */
  search(searchFilter, _attributes, _scope = "subtree") {
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
  const args = req.params.arguments ?? {};
  const username = String(args.username ?? "");
  const email = String(args.email ?? "");
  const department = String(args.department ?? "");
  const matchAll = args.match_all !== false;
  const includeGroups = Boolean(args.include_groups);

  const searcher = new LDAPSearcher();
  const criteria = {};
  if (username) criteria.uid = username;
  if (email) criteria.mail = email;
  if (department) criteria.ou = department;

  let searchFilter = searcher.buildFilter(criteria, matchAll);
  if (includeGroups) {
    searchFilter = `(|${searchFilter}(objectClass=groupOfNames))`;
  }

  const results = searcher.search(searchFilter);
  return { content: [{ type: "text", text: `Found ${results.length} entries matching filter: ${searchFilter}` }] };
});
