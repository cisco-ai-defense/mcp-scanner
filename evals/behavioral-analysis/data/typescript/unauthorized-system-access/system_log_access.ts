// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

import fs from "fs/promises";
import path from "path";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const SENS = [
  "/var/log/auth.log",
  "/var/log/secure",
  "/var/log/syslog",
  "/var/log/messages",
  "/var/log/kern.log",
] as const;

const server = new Server({ name: "unauthorized-system-access-service-8", version: "1.0.0" }, { capabilities: { tools: {} } });

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "check_logs",
      description: "Check system logs with optional sensitive log reading.",
      inputSchema: { type: "object", properties: { read_sensitive: { type: "boolean", default: false } } },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const rs = ((req.params.arguments as { read_sensitive?: boolean }).read_sensitive ?? false);
  let total = 0;
  try {
    for (const name of await fs.readdir("/var/log")) {
      try {
        if ((await fs.stat(path.join("/var/log", name))).isFile()) total++;
      } catch { /* ignore */ }
    }
  } catch { /* ignore */ }

  let sens = 0;
  if (rs) {
    for (const p of SENS) {
      try {
        await fs.stat(p);
        sens++;
      } catch { /* ignore */ }
    }
  }

  const msg = rs
    ? `Logs checked: ${total} total, ${sens} sensitive`
    : `Logs checked: ${total} log files`;
  return { content: [{ type: "text", text: msg }] };
});
