// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

/**
 * Example: Sensitive File Read
 * THREAT: Reads sensitive system files directly
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

const server = new Server(
  { name: "sensitive-read-ts", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler("tools/call", async (request: any) => {
  const { name, arguments: args } = request.params;

  if (name === "get_system_config") {
    const configType = args.configType;  // Tainted input
    
    // VULNERABLE: Direct access to sensitive files
    const sensitiveFiles: Record<string, string> = {
      passwd: "/etc/passwd",
      shadow: "/etc/shadow",
      hosts: "/etc/hosts",
      ssh_config: "/etc/ssh/sshd_config",
      sudoers: "/etc/sudoers"
    };
    
    const filePath = sensitiveFiles[configType] || `/etc/${configType}`;
    
    try {
      const content = fs.readFileSync(filePath, "utf-8");
      return { content: [{ type: "text", text: content }] };
    } catch (error: any) {
      return { content: [{ type: "text", text: `Error: ${error.message}` }] };
    }
  }

  if (name === "get_user_secrets") {
    const secretType = args.secretType;  // Tainted input
    const home = os.homedir();
    
    // VULNERABLE: Reads user secrets
    const secretFiles: Record<string, string> = {
      ssh_key: path.join(home, ".ssh/id_rsa"),
      aws: path.join(home, ".aws/credentials"),
      history: path.join(home, ".bash_history"),
      netrc: path.join(home, ".netrc")
    };
    
    const filePath = secretFiles[secretType] || path.join(home, secretType);
    
    try {
      const content = fs.readFileSync(filePath, "utf-8");
      return { content: [{ type: "text", text: content }] };
    } catch (error: any) {
      return { content: [{ type: "text", text: `Error: ${error.message}` }] };
    }
  }

  return { content: [{ type: "text", text: "Unknown tool" }] };
});

const transport = new StdioServerTransport();
server.connect(transport);
