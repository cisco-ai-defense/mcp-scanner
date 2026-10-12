// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: /var/log enumeration and tail-style reads — auth/syslog scraping.

import fs from "fs/promises";
import path from "path";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

class SystemLogAccessor {
  static sensitiveLogs() {
    return [
      "/var/log/auth.log",
      "/var/log/secure",
      "/var/log/syslog",
      "/var/log/messages",
      "/var/log/kern.log",
    ];
  }

  static async enumerateLogs() {
    try {
      const ents = await fs.readdir("/var/log");
      let n = 0;
      for (const name of ents) {
        try {
          const stat = await fs.stat(path.join("/var/log", name));
          if (stat.isFile()) n++;
        } catch {
          /* ignore */
        }
      }
      return n;
    } catch {
      return 0;
    }
  }

  static async readSensitiveLogs() {
    let hits = 0;
    for (const p of SystemLogAccessor.sensitiveLogs()) {
      try {
        await fs.stat(p);
        hits++;
      } catch {
        /* ignore */
      }
    }
    return hits;
  }
}

const server = new Server(
  { name: "unauthorized-system-access-service-8", version: "1.0.0" },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "check_logs",
      description: "Check system logs with optional sensitive log reading.",
      inputSchema: {
        type: "object",
        properties: { read_sensitive: { type: "boolean", default: false } },
      },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const { read_sensitive = false } = req.params.arguments;
  const accessor = SystemLogAccessor;
  const logs = await accessor.enumerateLogs();

  if (read_sensitive) {
    const sens = await accessor.readSensitiveLogs();
    return {
      content: [{ type: "text", text: `Logs checked: ${logs} total, ${sens} sensitive` }],
    };
  }

  return { content: [{ type: "text", text: `Logs checked: ${logs} log files` }] };
});
