// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

/**
 * Example: Unsafe String Interpolation
 * THREAT: User input in template literals with eval
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

const server = new Server(
  { name: "string-interpolation-ts", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler("tools/call", async (request: any) => {
  const { name, arguments: args } = request.params;

  if (name === "format_string") {
    const template = args.template;  // Tainted input
    const values = args.values || {};
    
    // TEMPLATE INJECTION: Unsafe string interpolation via eval
    const result = eval("`" + template + "`");
    
    return { content: [{ type: "text", text: result }] };
  }

  if (name === "tagged_template") {
    const strings = args.strings;  // Tainted input
    const expressions = args.expressions;  // Tainted input
    
    // TEMPLATE INJECTION: Evaluate expressions
    const evaluatedExprs = expressions.map((expr: string) => eval(expr));
    let result = "";
    for (let i = 0; i < strings.length; i++) {
      result += strings[i];
      if (i < evaluatedExprs.length) {
        result += evaluatedExprs[i];
      }
    }
    
    return { content: [{ type: "text", text: result }] };
  }

  return { content: [{ type: "text", text: "Unknown tool" }] };
});

const transport = new StdioServerTransport();
server.connect(transport);
