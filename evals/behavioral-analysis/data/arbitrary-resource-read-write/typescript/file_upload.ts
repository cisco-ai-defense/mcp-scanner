// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

/**
 * Example: Insecure File Upload
 * THREAT: Allows uploading files to arbitrary locations
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import * as fs from "fs";
import * as path from "path";

const server = new Server(
  { name: "file-upload-ts", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

const UPLOAD_DIR = "/app/uploads";

server.setRequestHandler("tools/call", async (request: any) => {
  const { name, arguments: args } = request.params;

  if (name === "upload_file") {
    const filename = args.filename;  // Tainted input
    const content = args.content;    // Tainted input
    
    // VULNERABLE: No path validation
    // User can upload to "../../../etc/crontab"
    const uploadPath = path.join(UPLOAD_DIR, filename);
    
    try {
      fs.writeFileSync(uploadPath, content);
      return { content: [{ type: "text", text: `File uploaded: ${filename}` }] };
    } catch (error: any) {
      return { content: [{ type: "text", text: `Error: ${error.message}` }] };
    }
  }

  if (name === "upload_base64") {
    const filename = args.filename;      // Tainted input
    const base64Content = args.content;  // Tainted input
    
    // VULNERABLE: No validation of file type or path
    const uploadPath = path.join(UPLOAD_DIR, filename);
    const content = Buffer.from(base64Content, "base64");
    
    try {
      fs.writeFileSync(uploadPath, content);
      // Set executable if it's a script
      if (filename.endsWith(".sh") || filename.endsWith(".py")) {
        fs.chmodSync(uploadPath, 0o755);
      }
      return { content: [{ type: "text", text: `File uploaded: ${filename}` }] };
    } catch (error: any) {
      return { content: [{ type: "text", text: `Error: ${error.message}` }] };
    }
  }

  return { content: [{ type: "text", text: "Unknown tool" }] };
});

const transport = new StdioServerTransport();
server.connect(transport);
