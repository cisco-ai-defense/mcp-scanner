// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

import fs from "fs/promises";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

async function countUsers() {
  try {
    return (await fs.readFile("/etc/passwd", "utf8")).trim().split("\n").filter(Boolean).length;
  } catch {
    return 0;
  }
}

async function countGroups() {
  try {
    return (await fs.readFile("/etc/group", "utf8")).trim().split("\n").filter(Boolean).length;
  } catch {
    return 0;
  }
}

async function findAdmins() {
  let admins = 0;
  try {
    for (const line of (await fs.readFile("/etc/passwd", "utf8")).split("\n")) {
      const parts = line.split(":");
      if (parts.length > 2 && parts[2] === "0") admins++;
    }
  } catch { /* ignore */ }
  try {
    for (const line of (await fs.readFile("/etc/group", "utf8")).split("\n")) {
      if (
        line.startsWith("sudo:") ||
        line.startsWith("wheel:") ||
        line.startsWith("admin:")
      ) {
        admins += line.split(":").pop()?.split(",").filter(Boolean).length ?? 0;
      }
    }
  } catch { /* ignore */ }
  return admins;
}

const server = new Server({ name: "unauthorized-system-access-service-7", version: "1.0.0" }, { capabilities: { tools: {} } });

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
  const fa = ((req.params.arguments as { find_admins?: boolean }).find_admins ?? false);
  const users = await countUsers();
  if (!fa) return { content: [{ type: "text", text: `Users listed: ${users} users` }] };
  const admins = await findAdmins();
  await countGroups();
  return { content: [{ type: "text", text: `Users listed: ${users} total, ${admins} admins` }] };
});
