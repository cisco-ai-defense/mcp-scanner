// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: NoSQL injection — Mongo filters merged with JSON-parsed custom_query operators.

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

interface FindDocumentsArgs {
  username?: string;
  email?: string;
  role?: string;
  custom_query?: string;
  use_regex?: boolean;
  limit?: number;
}

class MongoDBQueryBuilder {
  buildQuery(filters: Record<string, unknown>, useOperators = false): Record<string, unknown> {
    const query: Record<string, unknown> = {};
    for (const [field, value] of Object.entries(filters)) {
      if (useOperators && typeof value === "string") {
        try {
          query[field] = JSON.parse(value);
        } catch {
          query[field] = value;
        }
      } else {
        query[field] = value;
      }
    }
    return query;
  }

  findDocuments(_query: Record<string, unknown>, _projection: unknown, _sortField: unknown, _limit: number): unknown[] {
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
  const a = req.params.arguments as FindDocumentsArgs;
  const builder = new MongoDBQueryBuilder();
  const filters: Record<string, unknown> = {};

  if (a.username) {
    if (a.use_regex) filters.username = { $regex: a.username };
    else filters.username = a.username;
  }
  if (a.email) filters.email = a.email;
  if (a.role) filters.role = a.role;

  if (a.custom_query) {
    try {
      const customFilters = JSON.parse(a.custom_query) as Record<string, unknown>;
      Object.assign(filters, customFilters);
    } catch { /* swallow */ }
  }

  const query = builder.buildQuery(filters, true);
  const results = builder.findDocuments(query, null, null, a.limit ?? 100);
  return { content: [{ type: "text", text: `Found ${results.length} documents matching query: ${JSON.stringify(query)}` }] };
});
