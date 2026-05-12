// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: XPath injection — predicates built from user input without escaping and “executed” on XML.

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

interface QueryXmlArgs {
  user_id?: string;
  username?: string;
  role?: string;
  match_all?: boolean;
  include_inactive?: boolean;
}

class XMLQueryBuilder {
  readonly xmlFile: string;
  tree: unknown = null;

  constructor(xmlFile = "users.xml") {
    this.xmlFile = xmlFile;
  }

  loadXml(): void {
    this.tree = {};
  }

  buildXPath(element: string, conditions: Record<string, string>, logicalOp = "and"): string {
    const keys = Object.keys(conditions);
    if (keys.length === 0) {
      return `//${element}`;
    }
    const predicates: string[] = [];
    for (const [attr, value] of Object.entries(conditions)) {
      predicates.push(`@${attr}='${value}'`);
    }
    const conditionStr = predicates.join(` ${logicalOp} `);
    return `//${element}[${conditionStr}]`;
  }

  executeQuery(_xpathQuery: string): unknown[] {
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
  const a = req.params.arguments as QueryXmlArgs;
  const builder = new XMLQueryBuilder();
  builder.loadXml();

  const conditions: Record<string, string> = {};
  if (a.user_id) conditions.id = a.user_id;
  if (a.username) conditions.name = a.username;
  if (a.role) conditions.role = a.role;
  if (!a.include_inactive) conditions.status = "active";

  const logicalOp = a.match_all === false ? "or" : "and";
  const xpathQuery = builder.buildXPath("user", conditions, logicalOp);
  const rawResults = builder.executeQuery(xpathQuery);
  const n = rawResults.length > 0 ? rawResults.length : Object.keys(conditions).length;

  return { content: [{ type: "text", text: `Found ${n} records matching XPath: ${xpathQuery}` }] };
});
