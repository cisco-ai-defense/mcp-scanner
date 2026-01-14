// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Example 1: Path Traversal via Arbitrary File Read/Write
 * THREAT: User input allows reading/writing files outside intended directory
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import * as fs from "fs";
import * as path from "path";

const server = new Server(
  { name: "path-traversal-ts-1", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

const BASE_DIR = "/app/data";

// THREAT: Path Traversal - user input allows reading arbitrary files
server.setRequestHandler("tools/call", async (request: any) => {
  const { name, arguments: args } = request.params;

  if (name === "read_file") {
    const filename = args.filename;  // Tainted input
    
    // VULNERABLE: No path validation
    // User can inject: "../../../etc/passwd" or "....//....//etc/shadow"
    const fullPath = path.join(BASE_DIR, filename);
    
    try {
      const content = fs.readFileSync(fullPath, "utf-8");
      return {
        content: [{
          type: "text",
          text: content
        }]
      };
    } catch (error: any) {
      return {
        content: [{
          type: "text",
          text: `Error reading file: ${error.message}`
        }]
      };
    }
  }

  return { content: [{ type: "text", text: "Unknown tool" }] };
});

// THREAT: Path Traversal - arbitrary file write
server.setRequestHandler("tools/call", async (request: any) => {
  const { name, arguments: args } = request.params;

  if (name === "write_file") {
    const filename = args.filename;  // Tainted input
    const content = args.content;    // Tainted input
    
    // VULNERABLE: No path validation for write
    // User can inject: "../../../etc/crontab" or "~/.ssh/authorized_keys"
    const fullPath = path.join(BASE_DIR, filename);
    
    try {
      fs.writeFileSync(fullPath, content);
      return {
        content: [{
          type: "text",
          text: `File written successfully: ${filename}`
        }]
      };
    } catch (error: any) {
      return {
        content: [{
          type: "text",
          text: `Error writing file: ${error.message}`
        }]
      };
    }
  }

  return { content: [{ type: "text", text: "Unknown tool" }] };
});

// THREAT: Path Traversal via symlink following
server.setRequestHandler("tools/call", async (request: any) => {
  const { name, arguments: args } = request.params;

  if (name === "list_directory") {
    const dirPath = args.path;  // Tainted input
    
    // VULNERABLE: Follows symlinks without validation
    // User can create symlink to sensitive directory
    const fullPath = path.join(BASE_DIR, dirPath);
    
    try {
      const entries = fs.readdirSync(fullPath, { withFileTypes: true });
      const listing = entries.map(e => `${e.isDirectory() ? "[DIR]" : "[FILE]"} ${e.name}`);
      
      return {
        content: [{
          type: "text",
          text: listing.join("\n")
        }]
      };
    } catch (error: any) {
      return {
        content: [{
          type: "text",
          text: `Error listing directory: ${error.message}`
        }]
      };
    }
  }

  return { content: [{ type: "text", text: "Unknown tool" }] };
});

// THREAT: Sensitive file access
server.setRequestHandler("tools/call", async (request: any) => {
  const { name, arguments: args } = request.params;

  if (name === "get_config") {
    const configName = args.configName;  // Tainted input
    
    // VULNERABLE: Direct access to sensitive paths
    const sensitiveConfigs: Record<string, string> = {
      "ssh": "/etc/ssh/sshd_config",
      "passwd": "/etc/passwd",
      "shadow": "/etc/shadow",
      "hosts": "/etc/hosts"
    };
    
    const configPath = sensitiveConfigs[configName] || `/etc/${configName}`;
    
    try {
      const content = fs.readFileSync(configPath, "utf-8");
      return {
        content: [{
          type: "text",
          text: content
        }]
      };
    } catch (error: any) {
      return {
        content: [{
          type: "text",
          text: `Error reading config: ${error.message}`
        }]
      };
    }
  }

  return { content: [{ type: "text", text: "Unknown tool" }] };
});

const transport = new StdioServerTransport();
server.connect(transport);
