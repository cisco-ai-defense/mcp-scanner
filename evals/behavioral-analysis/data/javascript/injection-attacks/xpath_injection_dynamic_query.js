// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: XPath injection — predicates built from user input without escaping and “executed” on XML.

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

class XMLQueryBuilder {
  constructor(xmlFile = "users.xml") {
    this.xmlFile = xmlFile;
    this.tree = null;
  }

  loadXml() {
    // No-op if file absent — eval simulates execution only
    this.tree = {};
  }

  buildXPath(element, conditions, logicalOp = "and") {
    if (!conditions || Object.keys(conditions).length === 0) {
      return `//${element}`;
    }
    const predicates = [];
    for (const [attr, value] of Object.entries(conditions)) {
      // VULNERABLE: No escaping of XPath special characters
      predicates.push(`@${attr}='${value}'`);
    }
    const conditionStr = predicates.join(` ${logicalOp} `);
    return `//${element}[${conditionStr}]`;
  }

  /** Simulated XPath execution length for eval messaging. */
  executeQuery(_xpathQuery) {
    return [];
  }
}

const server = new Server(
  { name: "injection-attacks-service-6", version: "1.0.0" },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [{
    name: "query_xml",
    description: "Query XML database for user records with flexible filtering.",
    inputSchema: {
      type: "object",
      properties: {
        user_id: { type: "string", default: "" },
        username: { type: "string", default: "" },
        role: { type: "string", default: "" },
        match_all: { type: "boolean", default: true },
        include_inactive: { type: "boolean", default: false },
      },
    },
  }],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const args = req.params.arguments ?? {};
  const builder = new XMLQueryBuilder();
  builder.loadXml();

  const conditions = {};
  if (args.user_id) conditions.id = String(args.user_id);
  if (args.username) conditions.name = String(args.username);
  if (args.role) conditions.role = String(args.role);
  if (!args.include_inactive) conditions.status = "active";

  const logicalOp = args.match_all === false ? "or" : "and";
  const xpathQuery = builder.buildXPath("user", conditions, logicalOp);

  const rawResults = builder.executeQuery(xpathQuery);
  const n = rawResults.length > 0 ? rawResults.length : Object.keys(conditions).length;

  return { content: [{ type: "text", text: `Found ${n} records matching XPath: ${xpathQuery}` }] };
});
