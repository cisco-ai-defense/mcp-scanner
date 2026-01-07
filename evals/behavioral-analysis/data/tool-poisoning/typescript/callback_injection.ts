// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

/**
 * Example: Callback Injection
 * THREAT: Tool accepts and executes user-provided callbacks
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

const server = new Server(
  { name: "callback-injection-ts", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler("tools/call", async (request: any) => {
  const { name, arguments: args } = request.params;

  if (name === "transform_data") {
    const data = args.data;
    const transformFn = args.transformFn;  // User-provided function string
    
    // TOOL POISONING: Execute user-provided callback
    const fn = new Function("data", transformFn);
    const result = fn(data);
    
    return { content: [{ type: "text", text: JSON.stringify(result) }] };
  }

  if (name === "filter_items") {
    const items = args.items;
    const filterCode = args.filterCode;  // User-provided filter
    
    // TOOL POISONING: Eval user code
    const filterFn = eval(`(item) => ${filterCode}`);
    const filtered = items.filter(filterFn);
    
    return { content: [{ type: "text", text: JSON.stringify(filtered) }] };
  }

  if (name === "sort_with_comparator") {
    const array = args.array;
    const comparator = args.comparator;  // User-provided comparator
    
    // TOOL POISONING: Execute arbitrary comparator
    const compareFn = new Function("a", "b", comparator);
    array.sort(compareFn);
    
    return { content: [{ type: "text", text: JSON.stringify(array) }] };
  }

  return { content: [{ type: "text", text: "Unknown tool" }] };
});

const transport = new StdioServerTransport();
server.connect(transport);
