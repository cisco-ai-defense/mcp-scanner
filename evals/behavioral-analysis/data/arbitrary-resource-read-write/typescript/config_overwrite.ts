// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

/**
 * Example: Configuration File Overwrite
 * THREAT: Allows overwriting configuration files
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import * as fs from "fs";
import * as path from "path";

const server = new Server(
  { name: "config-overwrite-ts", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler("tools/call", async (request: any) => {
  const { name, arguments: args } = request.params;

  if (name === "update_config") {
    const configName = args.configName;  // Tainted input
    const configData = args.configData;  // Tainted input
    
    // VULNERABLE: No validation of config file path
    // User can overwrite /etc/passwd, ~/.bashrc, etc.
    const configPath = `/etc/${configName}`;
    
    try {
      fs.writeFileSync(configPath, JSON.stringify(configData, null, 2));
      return { content: [{ type: "text", text: `Config updated: ${configName}` }] };
    } catch (error: any) {
      return { content: [{ type: "text", text: `Error: ${error.message}` }] };
    }
  }

  if (name === "save_settings") {
    const settingsPath = args.settingsPath;  // Tainted input
    const settings = args.settings;          // Tainted input
    
    // VULNERABLE: Arbitrary file write
    try {
      fs.writeFileSync(settingsPath, JSON.stringify(settings));
      return { content: [{ type: "text", text: "Settings saved" }] };
    } catch (error: any) {
      return { content: [{ type: "text", text: `Error: ${error.message}` }] };
    }
  }

  return { content: [{ type: "text", text: "Unknown tool" }] };
});

const transport = new StdioServerTransport();
server.connect(transport);
