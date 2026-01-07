// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Example 2: SQL Injection via Dynamic Query Building
 * THREAT: User input directly interpolated into SQL queries
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

const server = new Server(
  { name: "injection-attacks-ts-2", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

interface DatabaseConnection {
  query(sql: string): Promise<any[]>;
}

// Simulated database connection
const db: DatabaseConnection = {
  async query(sql: string) {
    console.log("Executing:", sql);
    return [];
  }
};

// THREAT: SQL Injection - user input flows to SQL query
server.setRequestHandler("tools/call", async (request: any) => {
  const { name, arguments: args } = request.params;

  if (name === "search_users") {
    const username = args.username;  // Tainted input
    const email = args.email;        // Tainted input
    const role = args.role;          // Tainted input

    // VULNERABLE: Direct string interpolation in SQL
    // User can inject: "admin' OR '1'='1" or "'; DROP TABLE users; --"
    let query = `SELECT * FROM users WHERE 1=1`;

    if (username) {
      query += ` AND username = '${username}'`;
    }
    if (email) {
      query += ` AND email = '${email}'`;
    }
    if (role) {
      query += ` AND role = '${role}'`;
    }

    try {
      const results = await db.query(query);
      return {
        content: [{
          type: "text",
          text: `Found ${results.length} users`
        }]
      };
    } catch (error) {
      return { content: [{ type: "text", text: "Query failed" }] };
    }
  }

  return { content: [{ type: "text", text: "Unknown tool" }] };
});

// THREAT: SQL Injection with ORDER BY clause
server.setRequestHandler("tools/call", async (request: any) => {
  const { name, arguments: args } = request.params;

  if (name === "list_products") {
    const category = args.category;    // Tainted input
    const sortBy = args.sortBy;        // Tainted input
    const sortOrder = args.sortOrder;  // Tainted input
    const limit = args.limit || 10;

    // VULNERABLE: ORDER BY injection
    // User can inject sortBy: "price; DROP TABLE products; --"
    const query = `
      SELECT * FROM products 
      WHERE category = '${category}'
      ORDER BY ${sortBy} ${sortOrder}
      LIMIT ${limit}
    `;

    try {
      const results = await db.query(query);
      return {
        content: [{
          type: "text",
          text: JSON.stringify(results)
        }]
      };
    } catch (error) {
      return { content: [{ type: "text", text: "Query failed" }] };
    }
  }

  return { content: [{ type: "text", text: "Unknown tool" }] };
});

// THREAT: SQL Injection in LIKE clause
server.setRequestHandler("tools/call", async (request: any) => {
  const { name, arguments: args } = request.params;

  if (name === "search_documents") {
    const searchTerm = args.searchTerm;  // Tainted input
    const docType = args.docType;        // Tainted input

    // VULNERABLE: LIKE clause injection
    // User can inject: "%' UNION SELECT password FROM users WHERE '1'='1"
    const query = `
      SELECT id, title, content 
      FROM documents 
      WHERE title LIKE '%${searchTerm}%'
      AND doc_type = '${docType}'
    `;

    try {
      const results = await db.query(query);
      return {
        content: [{
          type: "text",
          text: `Found ${results.length} documents`
        }]
      };
    } catch (error) {
      return { content: [{ type: "text", text: "Search failed" }] };
    }
  }

  return { content: [{ type: "text", text: "Unknown tool" }] };
});

const transport = new StdioServerTransport();
server.connect(transport);
