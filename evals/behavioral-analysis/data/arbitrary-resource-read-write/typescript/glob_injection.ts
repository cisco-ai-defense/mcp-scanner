// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

/**
 * Example: Glob Pattern Injection
 * THREAT: User input in glob patterns allows reading unintended files
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import * as fs from "fs";
import * as path from "path";

const server = new Server(
  { name: "glob-injection-ts", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

// Simulated glob function
function glob(pattern: string): string[] {
  // In real code, this would use a glob library
  return [pattern];
}

server.setRequestHandler("tools/call", async (request: any) => {
  const { name, arguments: args } = request.params;

  if (name === "find_files") {
    const pattern = args.pattern;  // Tainted input
    const baseDir = args.baseDir || "/app/data";
    
    // VULNERABLE: User-controlled glob pattern
    // User can inject: "../../../etc/*" or "**/*.key"
    const fullPattern = path.join(baseDir, pattern);
    const files = glob(fullPattern);
    
    const results: string[] = [];
    for (const file of files) {
      try {
        const content = fs.readFileSync(file, "utf-8");
        results.push(`${file}: ${content.substring(0, 100)}`);
      } catch {}
    }
    
    return { content: [{ type: "text", text: results.join("\n") }] };
  }

  if (name === "delete_files") {
    const pattern = args.pattern;  // Tainted input
    
    // VULNERABLE: User-controlled deletion pattern
    const files = glob(pattern);
    
    for (const file of files) {
      try {
        fs.unlinkSync(file);
      } catch {}
    }
    
    return { content: [{ type: "text", text: `Deleted ${files.length} files` }] };
  }

  return { content: [{ type: "text", text: "Unknown tool" }] };
});

const transport = new StdioServerTransport();
server.connect(transport);
