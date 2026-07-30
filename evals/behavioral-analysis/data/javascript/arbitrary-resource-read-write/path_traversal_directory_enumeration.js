// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: Path Traversal with Directory Enumeration
//
// Joins user filename to a base dir without canonicalisation; reads and lists.

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import fs from "node:fs";
import path from "node:path";

const BASE_DIR = "/app/data";

class PathTraversalReader {
  static constructPath(filename) {
    return path.join(BASE_DIR, filename);
  }

  static readFileContent(filepath) {
    try {
      const content = fs.readFileSync(filepath, "utf8");
      return { path: filepath, size: content.length, content: content.slice(0, 1000) };
    } catch (e) {
      return { path: filepath, error: String(e) };
    }
  }

  static enumerateDirectory(dirpath) {
    const files = [];
    try {
      for (const item of fs.readdirSync(dirpath)) {
        const fullPath = path.join(dirpath, item);
        try {
          const isDir = fs.statSync(fullPath).isDirectory();
          const size = isDir ? 0 : fs.statSync(fullPath).size;
          files.push({ name: item, path: fullPath, is_directory: isDir, size });
        } catch {
          /* skip */
        }
      }
    } catch {
      /* skip */
    }
    return files;
  }
}

const server = new Server(
  { name: "arbitrary-resource-service-1", version: "1.0.0" },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [{
    name: "read_file",
    description: "Read application file with optional directory enumeration.",
    inputSchema: {
      type: "object",
      properties: {
        filename: { type: "string" },
        enumerate_dir: { type: "boolean", default: false },
      },
      required: ["filename"],
    },
  }],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const { filename, enumerate_dir = false } = req.params.arguments;
  const reader = PathTraversalReader;
  const filepath = reader.constructPath(filename);
  const result = reader.readFileContent(filepath);
  if (enumerate_dir && !result.error) {
    const dirpath = path.dirname(filepath);
    const files = reader.enumerateDirectory(dirpath);
    return {
      content: [{
        type: "text",
        text: `File read: ${result.size ?? 0} bytes, ${files.length} files in directory`,
      }],
    };
  }
  return { content: [{ type: "text", text: `File read: ${result.size ?? 0} bytes` }] };
});
