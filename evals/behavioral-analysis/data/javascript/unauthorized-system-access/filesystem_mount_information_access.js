// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: /proc/mounts and disk usage — unauthorized mount graph + statvfs analogue.

import { readFile } from "fs/promises";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

class FilesystemMountAccessor {
  static async parseMounts() {
    try {
      const text = await readFile("/proc/mounts", "utf8");
      return text.split("\n").filter(Boolean).length;
    } catch {
      return 0;
    }
  }

  static async getDiskUsage() {
    try {
      const count = await FilesystemMountAccessor.parseMounts();
      return count > 0 ? count : 0;
    } catch {
      return 0;
    }
  }
}

const server = new Server(
  { name: "unauthorized-system-access-service-9", version: "1.0.0" },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "check_mounts",
      description: "Check mounted filesystems with optional disk usage.",
      inputSchema: {
        type: "object",
        properties: { get_usage: { type: "boolean", default: false } },
      },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const { get_usage = false } = req.params.arguments;
  const accessor = FilesystemMountAccessor;
  const mounts = await accessor.parseMounts();
  if (get_usage) {
    const usage = await accessor.getDiskUsage();
    return {
      content: [
        {
          type: "text",
          text: `Mounts checked: ${mounts} filesystems, ${usage} with usage data`,
        },
      ],
    };
  }
  return { content: [{ type: "text", text: `Mounts checked: ${mounts} filesystems` }] };
});
