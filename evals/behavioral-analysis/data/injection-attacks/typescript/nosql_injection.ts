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
 * Example 3: NoSQL Injection via MongoDB Query
 * THREAT: User input flows to MongoDB query operators
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

const server = new Server(
  { name: "injection-attacks-ts-3", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

// Simulated MongoDB collection
const db = {
  collection: (name: string) => ({
    find: async (query: any) => {
      console.log("MongoDB query:", JSON.stringify(query));
      return { toArray: async () => [] };
    },
    findOne: async (query: any) => {
      console.log("MongoDB findOne:", JSON.stringify(query));
      return null;
    }
  })
};

// THREAT: NoSQL Injection - user input in MongoDB query
server.setRequestHandler("tools/call", async (request: any) => {
  const { name, arguments: args } = request.params;

  if (name === "find_user") {
    const username = args.username;  // Tainted input
    const password = args.password;  // Tainted input
    
    // VULNERABLE: Direct use of user input in query
    // User can inject: { "$gt": "" } to bypass authentication
    // Or: { "$ne": null } to match any document
    const query = {
      username: username,
      password: password
    };
    
    try {
      const user = await db.collection("users").findOne(query);
      
      if (user) {
        return {
          content: [{
            type: "text",
            text: `User found: ${JSON.stringify(user)}`
          }]
        };
      } else {
        return {
          content: [{
            type: "text",
            text: "User not found"
          }]
        };
      }
    } catch (error: any) {
      return {
        content: [{
          type: "text",
          text: `Query error: ${error.message}`
        }]
      };
    }
  }

  return { content: [{ type: "text", text: "Unknown tool" }] };
});

// THREAT: NoSQL Injection via $where operator
server.setRequestHandler("tools/call", async (request: any) => {
  const { name, arguments: args } = request.params;

  if (name === "search_products") {
    const searchTerm = args.searchTerm;  // Tainted input
    const minPrice = args.minPrice;
    const maxPrice = args.maxPrice;
    
    // VULNERABLE: $where with user input allows JavaScript execution
    // User can inject: "this.price > 0; while(1){}" for DoS
    // Or: "this.price > 0; return true" to bypass filters
    const query = {
      $where: `this.name.includes('${searchTerm}') && this.price >= ${minPrice} && this.price <= ${maxPrice}`
    };
    
    try {
      const results = await db.collection("products").find(query);
      const products = await results.toArray();
      
      return {
        content: [{
          type: "text",
          text: `Found ${products.length} products`
        }]
      };
    } catch (error: any) {
      return {
        content: [{
          type: "text",
          text: `Search error: ${error.message}`
        }]
      };
    }
  }

  return { content: [{ type: "text", text: "Unknown tool" }] };
});

const transport = new StdioServerTransport();
server.connect(transport);
