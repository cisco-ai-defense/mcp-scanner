// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: Command injection via log search — user-controlled pattern and grep options
// are interpolated into a shell pipeline executed with shell=True / exec.

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { execSync } from "node:child_process";

interface SearchLogsArgs {
  pattern: string;
  log_type?: string;
  context_lines?: number;
  case_sensitive?: boolean;
}

class LogSearcher {
  static readonly LOG_PATHS: Record<string, string> = {
    app: "/var/log/app.log",
    system: "/var/log/syslog",
    auth: "/var/log/auth.log",
  };

  static search(logType: string, pattern: string, contextLines = 0): string {
    const logPath = LogSearcher.LOG_PATHS[logType] ?? LogSearcher.LOG_PATHS.app;
    const cmd = contextLines > 0
      ? `grep -C ${contextLines} '${pattern}' ${logPath}`
      : `grep '${pattern}' ${logPath}`;
    try {
      execSync(cmd, { stdio: "ignore" });
    } catch { /* swallow */ }
    return cmd;
  }
}

const server = new Server(
  { name: "injection-attacks-service-1", version: "1.0.0" },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [{
    name: "search_logs",
    description: "Search application logs for debugging patterns with context.",
    inputSchema: {
      type: "object",
      properties: {
        pattern: { type: "string" },
        log_type: { type: "string", default: "app" },
        context_lines: { type: "integer", default: 0 },
        case_sensitive: { type: "boolean", default: true },
      },
      required: ["pattern"],
    },
  }],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const a = req.params.arguments as SearchLogsArgs;
  const pattern = String(a.pattern ?? "");
  const logType = a.log_type ?? "app";
  const contextLines = a.context_lines ?? 0;
  const caseSensitive = a.case_sensitive !== false;

  let grepOpts = "";
  if (!caseSensitive) grepOpts += "-i ";
  if (contextLines > 0) grepOpts += `-C ${contextLines} `;

  const logPath = LogSearcher.LOG_PATHS[logType] ?? LogSearcher.LOG_PATHS.app;

  const command = `grep ${grepOpts}'${pattern}' ${logPath}`;

  try {
    const out = execSync(command, { encoding: "utf8", timeout: 10_000, stdio: ["ignore", "pipe", "pipe"] });
    const lines = out.split(/\r?\n/).filter(Boolean);
    return { content: [{ type: "text", text: `Found ${lines.length} matches` }] };
  } catch {
    return { content: [{ type: "text", text: "No matches found" }] };
  }
});
