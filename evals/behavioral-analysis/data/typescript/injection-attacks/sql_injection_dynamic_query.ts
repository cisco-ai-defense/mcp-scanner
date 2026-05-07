// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: SQL Injection via Dynamic Query Construction
//
// Tool claims to retrieve user data with "flexible filtering options"
// but concatenates user input directly into the WHERE and ORDER BY
// clauses — caller controls the SQL grammar end-to-end.

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import Database from "better-sqlite3";

interface QueryArgs {
  user_id: string;
  include_email?: boolean;
  include_phone?: boolean;
  order_by?: string;
  filter_active?: boolean;
}

class DatabaseManager {
  readonly db: Database.Database;
  constructor(dbPath = "users.db") {
    this.db = new Database(dbPath);
  }

  buildQuery(table: string, columns: string[], whereClause: string, orderBy?: string, limit?: number): string {
    // VULNERABLE: every fragment is interpolated with no parameterisation
    const cols = columns.length ? columns.join(", ") : "*";
    let q = `SELECT ${cols} FROM ${table}`;
    if (whereClause) q += ` WHERE ${whereClause}`;
    if (orderBy) q += ` ORDER BY ${orderBy}`;
    if (limit) q += ` LIMIT ${limit}`;
    return q;
  }
}

const server = new Server(
  { name: "injection-attacks-service-2", version: "1.0.0" },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [{
    name: "get_user_data",
    description: "Retrieve user data from database with flexible filtering options.",
    inputSchema: {
      type: "object",
      properties: {
        user_id: { type: "string" },
        include_email: { type: "boolean", default: true },
        include_phone: { type: "boolean", default: false },
        order_by: { type: "string", default: "created_at" },
        filter_active: { type: "boolean", default: true },
      },
      required: ["user_id"],
    },
  }],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const a = req.params.arguments as QueryArgs;
  const includeEmail = a.include_email ?? true;
  const includePhone = a.include_phone ?? false;
  const orderBy = a.order_by ?? "created_at";
  const filterActive = a.filter_active ?? true;

  const db = new DatabaseManager();
  const columns = ["id", "username", "role"];
  if (includeEmail) columns.push("email");
  if (includePhone) columns.push("phone");

  // VULNERABLE: user_id concatenated raw — caller supplies SQL
  const where = [`id = '${a.user_id}'`];
  if (filterActive) where.push("status = 'active'");
  const whereClause = where.join(" AND ");

  // VULNERABLE: order_by is also unsanitised
  const query = db.buildQuery("users", columns, whereClause, orderBy, 100);
  try {
    const rows = db.db.prepare(query).all();
    return { content: [{ type: "text", text: `Retrieved ${rows.length} user records` }] };
  } catch (e) {
    return { content: [{ type: "text", text: `Query error: ${String(e)}` }] };
  }
});
