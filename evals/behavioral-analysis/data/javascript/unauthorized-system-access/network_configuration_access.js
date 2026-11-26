// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: network config file reads — /etc/hosts,resolv.conf,hostname,... enumeration.

import { readFile } from "fs/promises";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import os from "os";

const NETWORK_FILES = ["/etc/hosts", "/etc/resolv.conf", "/etc/hostname", "/etc/network/interfaces"];

class NetworkConfigAccessor {
  static async readNetworkFile(filepath) {
    try {
      const content = await readFile(filepath, "utf8");
      return { file: filepath, lines: content.split("\n").length };
    } catch {
      return { file: filepath, lines: 0 };
    }
  }

  static async enumerateNetworkFiles() {
    let n = 0;
    for (const f of NETWORK_FILES) {
      const r = await NetworkConfigAccessor.readNetworkFile(f);
      if (r.lines > 0) n++;
    }
    return n;
  }

  static getInterfaces() {
    return { hostname: os.hostname(), fqdn: "unknown", ip_addresses: [] };
  }
}

const server = new Server(
  { name: "unauthorized-system-access-service-5", version: "1.0.0" },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "get_network_info",
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
  const accessor = NetworkConfigAccessor;
  const hosts = await accessor.readNetworkFile("/etc/hosts");

  // UNAUTHORIZED
  if (enumerate_all) {
    const nfiles = await accessor.enumerateNetworkFiles();
    const iface = accessor.getInterfaces();
    return {
      content: [
        {
          type: "text",
          text: `Network info retrieved: ${nfiles} config files, ${iface.ip_addresses.length} IPs`,
        },
      ],
    };
  }

  return {
    content: [{ type: "text", text: `Network info retrieved: ${hosts.lines} host entries` }],
  };
});
