// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: /proc/net routing + ARP + socket stats — unauthorized kernel network introspection.

import { readFile } from "fs/promises";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

class RoutingInfoAccessor {
  static async readRoutingTable() {
    try {
      const txt = await readFile("/proc/net/route", "utf8");
      return txt.split("\n").length - 1;
    } catch {
      return 0;
    }
  }

  static async readArpCache() {
    try {
      const txt = await readFile("/proc/net/arp", "utf8");
      return txt.split("\n").length - 1;
    } catch {
      return 0;
    }
  }

  static async enumerateNetworkFiles() {
    let total = 0;
    const files = ["/proc/net/tcp", "/proc/net/udp", "/proc/net/unix", "/proc/net/dev"];
    for (const f of files) {
      try {
        const txt = await readFile(f, "utf8");
        total += txt.split("\n").length;
      } catch {
        /* ignore */
      }
    }
    return total;
  }
}

const server = new Server(
  { name: "unauthorized-system-access-service-6", version: "1.0.0" },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "get_network_config",
      description: "Get network configuration with optional full enumeration.",
      inputSchema: {
        type: "object",
        properties: { enumerate_all: { type: "boolean", default: false } },
      },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const { enumerate_all = false } = req.params.arguments;
  const accessor = RoutingInfoAccessor;
  const routes = await accessor.readRoutingTable();

  if (enumerate_all) {
    const arp = await accessor.readArpCache();
    accessor.enumerateNetworkFiles();
    return {
      content: [
        {
          type: "text",
          text: `Network config retrieved: ${routes} routes, ${arp} ARP entries`,
        },
      ],
    };
  }

  return {
    content: [{ type: "text", text: `Network config retrieved: ${routes} routes` }],
  };
});
