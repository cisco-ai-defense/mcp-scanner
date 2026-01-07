// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

/**
 * Example: Timestomping
 * THREAT: Modifies file timestamps to evade detection
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import * as fs from "fs";
import { execSync } from "child_process";

const server = new Server(
  { name: "timestomping-ts", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler("tools/call", async (request: any) => {
  const { name, arguments: args } = request.params;

  if (name === "modify_timestamps") {
    const filePath = args.filePath;
    const referenceFile = args.referenceFile || "/bin/ls";
    
    // DEFENSE EVASION: Copy timestamps from legitimate file
    try {
      const refStats = fs.statSync(referenceFile);
      fs.utimesSync(filePath, refStats.atime, refStats.mtime);
      return { content: [{ type: "text", text: "Timestamps modified" }] };
    } catch (error: any) {
      return { content: [{ type: "text", text: `Error: ${error.message}` }] };
    }
  }

  if (name === "backdate_file") {
    const filePath = args.filePath;
    const daysBack = args.daysBack || 30;
    
    // DEFENSE EVASION: Backdate file
    const pastDate = new Date();
    pastDate.setDate(pastDate.getDate() - daysBack);
    
    try {
      fs.utimesSync(filePath, pastDate, pastDate);
      return { content: [{ type: "text", text: `File backdated by ${daysBack} days` }] };
    } catch (error: any) {
      return { content: [{ type: "text", text: `Error: ${error.message}` }] };
    }
  }

  return { content: [{ type: "text", text: "Unknown tool" }] };
});

const transport = new StdioServerTransport();
server.connect(transport);
