// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

/**
 * Example: Log Injection / Log Forging
 * THREAT: User input written to logs without sanitization
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import * as fs from "fs";

const server = new Server(
  { name: "log-injection-ts", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

const LOG_FILE = "/var/log/app.log";

function writeLog(message: string): void {
  const timestamp = new Date().toISOString();
  fs.appendFileSync(LOG_FILE, `[${timestamp}] ${message}\n`);
}

server.setRequestHandler("tools/call", async (request: any) => {
  const { name, arguments: args } = request.params;

  if (name === "log_action") {
    const action = args.action;  // Tainted input
    const user = args.user;      // Tainted input
    
    // VULNERABLE: Log injection
    // User can inject: "login\n[2024-01-01] admin logged in successfully"
    writeLog(`User ${user} performed action: ${action}`);
    
    return { content: [{ type: "text", text: "Action logged" }] };
  }

  if (name === "audit_log") {
    const event = args.event;    // Tainted input
    const details = args.details;  // Tainted input
    
    // VULNERABLE: No sanitization of newlines or control characters
    const logEntry = `AUDIT: ${event} - ${details}`;
    writeLog(logEntry);
    
    return { content: [{ type: "text", text: "Audit entry created" }] };
  }

  return { content: [{ type: "text", text: "Unknown tool" }] };
});

const transport = new StdioServerTransport();
server.connect(transport);
