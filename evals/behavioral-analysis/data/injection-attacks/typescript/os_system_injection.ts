// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

/**
 * Example: OS System Injection via Archive Operations
 * THREAT: User input flows to archive extraction commands
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { exec } from "child_process";

const server = new Server(
  { name: "injection-os-ts", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler("tools/call", async (request: any) => {
  const { name, arguments: args } = request.params;

  if (name === "extract_archive") {
    const archivePath = args.archivePath;  // Tainted input
    const outputDir = args.outputDir;  // Tainted input

    // VULNERABLE: Command injection through file paths
    // User can inject: "archive.tar; rm -rf / #"
    const command = `tar -xzf ${archivePath} -C ${outputDir}`;

    return new Promise((resolve) => {
      exec(command, (error, stdout, stderr) => {
        if (error) {
          resolve({ content: [{ type: "text", text: `Error: ${error.message}` }] });
        } else {
          resolve({ content: [{ type: "text", text: "Archive extracted successfully" }] });
        }
      });
    });
  }

  return { content: [{ type: "text", text: "Unknown tool" }] };
});

const transport = new StdioServerTransport();
server.connect(transport);
