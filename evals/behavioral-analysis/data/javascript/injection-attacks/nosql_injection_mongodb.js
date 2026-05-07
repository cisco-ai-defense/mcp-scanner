// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: NoSQL injection — Mongo filters merged with JSON-parsed custom_query operators.

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

class MongoDBQueryBuilder {
  constructor(connectionString = "mongodb://localhost:27017/") {
    this.connectionString = connectionString;
    this.dbName = "mydb";
    this.collectionName = "users";
  }

  buildQuery(filters, useOperators = false) {
    const query = {};
    for (const [field, value] of Object.entries(filters)) {
      if (useOperators && typeof value === "string") {
        try {
          const parsedValue = JSON.parse(value);
          query[field] = parsedValue;
        } catch {
          query[field] = value;
        }
      } else {
        query[field] = value;
      }
    }
    return query;
  }

  /** Stub — never hits pymongo; mirrors Python empty-result path. */
  findDocuments(_query, _projection, _sortField, _limit) {
    return [];
  }
}

const server = new Server(
  { name: "injection-attacks-service-7", version: "1.0.0" },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [{
    name: "find_documents",
    description: "Find documents in MongoDB collection with flexible query options.",
    inputSchema: {
      type: "object",
      properties: {
        username: { type: "string", default: "" },
        email: { type: "string", default: "" },
        role: { type: "string", default: "" },
        custom_query: { type: "string", default: "" },
        use_regex: { type: "boolean", default: false },
        limit: { type: "integer", default: 100 },
      },
    },
  }],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const args = req.params.arguments ?? {};
  const builder = new MongoDBQueryBuilder();

  const filters = {};
  const username = String(args.username ?? "");
  const email = String(args.email ?? "");
  const role = String(args.role ?? "");
  const customQuery = String(args.custom_query ?? "");
  const useRegex = Boolean(args.use_regex);
  const limit = Number(args.limit ?? 100);

  if (username) {
    if (useRegex) filters.username = { $regex: username };
    else filters.username = username;
  }
  if (email) filters.email = email;
  if (role) filters.role = role;

  if (customQuery) {
    try {
      const customFilters = JSON.parse(customQuery);
      Object.assign(filters, customFilters);
    } catch { /* swallow like Python */ }
  }

  const query = builder.buildQuery(filters, true);
  const results = builder.findDocuments(query, null, null, limit);
  return { content: [{ type: "text", text: `Found ${results.length} documents matching query: ${JSON.stringify(query)}` }] };
});
