// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

/**
 * Example: Zip Slip Vulnerability
 * THREAT: Archive extraction allows writing files outside target directory
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import * as fs from "fs";
import * as path from "path";
import { execSync } from "child_process";

const server = new Server(
  { name: "zip-slip-ts", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

const EXTRACT_DIR = "/app/uploads";

server.setRequestHandler("tools/call", async (request: any) => {
  const { name, arguments: args } = request.params;

  if (name === "extract_archive") {
    const archivePath = args.archivePath;  // Tainted input
    
    // VULNERABLE: No validation of file paths in archive
    // Archive can contain "../../../etc/crontab" entries
    try {
      execSync(`unzip -o ${archivePath} -d ${EXTRACT_DIR}`);
      return { content: [{ type: "text", text: "Archive extracted" }] };
    } catch (error: any) {
      return { content: [{ type: "text", text: `Error: ${error.message}` }] };
    }
  }

  if (name === "extract_tar") {
    const tarPath = args.tarPath;  // Tainted input
    
    // VULNERABLE: tar extraction without path validation
    try {
      execSync(`tar -xf ${tarPath} -C ${EXTRACT_DIR}`);
      return { content: [{ type: "text", text: "Tar extracted" }] };
    } catch (error: any) {
      return { content: [{ type: "text", text: `Error: ${error.message}` }] };
    }
  }

  return { content: [{ type: "text", text: "Unknown tool" }] };
});

const transport = new StdioServerTransport();
server.connect(transport);
