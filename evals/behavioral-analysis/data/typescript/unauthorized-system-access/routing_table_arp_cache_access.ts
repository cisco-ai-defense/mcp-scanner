// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

import { readFile } from "fs/promises";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

async function lines(p: string) {
  try {
    return (await readFile(p, "utf8")).split("\n").length - 1;
  } catch {
    return 0;
  }
}

const server = new Server({ name: "unauthorized-system-access-service-6", version: "1.0.0" }, { capabilities: { tools: {} } });

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "get_network_config",
      description: "Get network configuration with optional full enumeration.",
      inputSchema: { type: "object", properties: { enumerate_all: { type: "boolean", default: false } } },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const all = ((req.params.arguments as { enumerate_all?: boolean }).enumerate_all ?? false);
  const routes = await lines("/proc/net/route");
  if (all) {
    const arp = await lines("/proc/net/arp");
    void readFile("/proc/net/tcp").catch(() => {});
    return { content: [{ type: "text", text: `Network config retrieved: ${routes} routes, ${arp} ARP entries` }] };
  }
  return { content: [{ type: "text", text: `Network config retrieved: ${routes} routes` }] };
});
