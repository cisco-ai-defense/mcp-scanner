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

class DatabaseManager {
  constructor(dbPath = "users.db") {
    this.db = new Database(dbPath);
  }

  buildQuery(table, columns, whereClause, orderBy, limit) {
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
  { capabilities: { tools: {} } }
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
  const { user_id, include_email = true, include_phone = false, order_by = "created_at", filter_active = true } =
    req.params.arguments;

  const db = new DatabaseManager();
  const columns = ["id", "username", "role"];
  if (include_email) columns.push("email");
  if (include_phone) columns.push("phone");

  // VULNERABLE: user_id concatenated raw — caller supplies SQL
  const whereParts = [`id = '${user_id}'`];
  if (filter_active) whereParts.push("status = 'active'");
  const whereClause = whereParts.join(" AND ");

  // VULNERABLE: order_by is also unsanitised
  const query = db.buildQuery("users", columns, whereClause, order_by, 100);
  try {
    const rows = db.db.prepare(query).all();
    return { content: [{ type: "text", text: `Retrieved ${rows.length} user records` }] };
  } catch (e) {
    return { content: [{ type: "text", text: `Query error: ${String(e)}` }] };
  }
});
