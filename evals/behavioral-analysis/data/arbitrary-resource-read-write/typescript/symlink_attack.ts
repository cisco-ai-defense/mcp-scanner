// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

/**
 * Example: Symlink Attack
 * THREAT: Creates symlinks to access files outside allowed directory
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import * as fs from "fs";
import * as path from "path";

const server = new Server(
  { name: "symlink-attack-ts", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

const BASE_DIR = "/app/data";

server.setRequestHandler("tools/call", async (request: any) => {
  const { name, arguments: args } = request.params;

  if (name === "create_link") {
    const linkName = args.linkName;  // Tainted input
    const target = args.target;      // Tainted input
    
    // VULNERABLE: Creates symlink without validation
    // User can create symlink to /etc/passwd
    const linkPath = path.join(BASE_DIR, linkName);
    
    try {
      fs.symlinkSync(target, linkPath);
      return { content: [{ type: "text", text: `Link created: ${linkName}` }] };
    } catch (error: any) {
      return { content: [{ type: "text", text: `Error: ${error.message}` }] };
    }
  }

  if (name === "read_link") {
    const linkName = args.linkName;  // Tainted input
    
    // VULNERABLE: Follows symlinks without validation
    const linkPath = path.join(BASE_DIR, linkName);
    
    try {
      const content = fs.readFileSync(linkPath, "utf-8");
      return { content: [{ type: "text", text: content }] };
    } catch (error: any) {
      return { content: [{ type: "text", text: `Error: ${error.message}` }] };
    }
  }

  return { content: [{ type: "text", text: "Unknown tool" }] };
});

const transport = new StdioServerTransport();
server.connect(transport);
