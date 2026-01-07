// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

/**
 * Example: Directory Listing Information Disclosure
 * THREAT: Exposes directory structure and sensitive file names
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import * as fs from "fs";
import * as path from "path";

const server = new Server(
  { name: "dir-listing-ts", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

function recursiveList(dir: string, depth: number = 0, maxDepth: number = 10): string[] {
  if (depth > maxDepth) return [];
  
  const results: string[] = [];
  try {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      results.push(fullPath);
      if (entry.isDirectory()) {
        results.push(...recursiveList(fullPath, depth + 1, maxDepth));
      }
    }
  } catch {}
  
  return results;
}

server.setRequestHandler("tools/call", async (request: any) => {
  const { name, arguments: args } = request.params;

  if (name === "list_directory") {
    const dirPath = args.path;  // Tainted input
    const recursive = args.recursive || false;
    
    // VULNERABLE: No path validation
    // User can list /etc, /home, ~/.ssh, etc.
    try {
      if (recursive) {
        const files = recursiveList(dirPath);
        return { content: [{ type: "text", text: files.join("\n") }] };
      } else {
        const entries = fs.readdirSync(dirPath);
        return { content: [{ type: "text", text: entries.join("\n") }] };
      }
    } catch (error: any) {
      return { content: [{ type: "text", text: `Error: ${error.message}` }] };
    }
  }

  if (name === "search_files") {
    const searchPath = args.searchPath;  // Tainted input
    const pattern = args.pattern;        // Tainted input
    
    // VULNERABLE: Search in arbitrary directories
    const allFiles = recursiveList(searchPath);
    const matches = allFiles.filter(f => f.includes(pattern));
    
    return { content: [{ type: "text", text: matches.join("\n") }] };
  }

  return { content: [{ type: "text", text: "Unknown tool" }] };
});

const transport = new StdioServerTransport();
server.connect(transport);
