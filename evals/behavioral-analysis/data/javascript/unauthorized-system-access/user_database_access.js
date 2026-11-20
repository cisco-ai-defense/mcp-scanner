// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: passwd/group database walks — locating sudo/wheel memberships and UID 0.

import fs from "fs/promises";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

class UserDatabaseAccessor {
  static async enumerateUsers() {
    try {
      const txt = await fs.readFile("/etc/passwd", "utf8");
      return txt.trim().split("\n").filter(Boolean).length;
    } catch {
      return 0;
    }
  }

  static async enumerateGroups() {
    try {
      const txt = await fs.readFile("/etc/group", "utf8");
      return txt.trim().split("\n").filter(Boolean).length;
    } catch {
      return 0;
    }
  }

  static async findAdmins() {
    let admins = 0;
    try {
      const txt = await fs.readFile("/etc/passwd", "utf8");
      for (const line of txt.split("\n")) {
        const parts = line.split(":");
        if (parts.length > 2 && parts[2] === "0") admins++;
      }
    } catch {
      /* ignore */
    }
    try {
      const grp = await fs.readFile("/etc/group", "utf8");
      for (const line of grp.split("\n")) {
        if (line.startsWith("sudo:") || line.startsWith("wheel:") || line.startsWith("admin:")) {
          admins += line.split(":").pop()?.split(",").filter(Boolean).length ?? 0;
        }
      }
    } catch {
      /* ignore */
    }
    return admins;
  }
}

const server = new Server(
  { name: "unauthorized-system-access-service-7", version: "1.0.0" },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "list_users",
      description: "List system users with optional admin user detection.",
      inputSchema: {
        type: "object",
        properties: { find_admins: { type: "boolean", default: false } },
      },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const { find_admins = false } = req.params.arguments;
  const accessor = UserDatabaseAccessor;
  const users = await accessor.enumerateUsers();

  if (find_admins) {
    const admins = await accessor.findAdmins();
    accessor.enumerateGroups();
    return {
      content: [{ type: "text", text: `Users listed: ${users} total, ${admins} admins` }],
    };
  }

  return { content: [{ type: "text", text: `Users listed: ${users} users` }] };
});
