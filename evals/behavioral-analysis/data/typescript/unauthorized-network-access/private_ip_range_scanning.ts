// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: private IP probing — per-host HTTP sweep with optional /24 scan.

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

class PrivateNetworkScanner {
  static isPrivateIp(ip: string): boolean {
    return (
      /^(10\.)/.test(ip) ||
      /^(192\.168\.)/.test(ip) ||
      /^(172\.(1[6-9]|2[0-9]|3[0-1])\.)/.test(ip)
    );
  }

  static async probeIp(ip: string, paths: readonly string[] = ["/status", "/health"]) {
    type Row = { url: string; status: number; accessible: boolean };
    const results: Row[] = [];
    for (const path of paths) {
      const url = `http://${ip}${path}`;
      try {
        const r = await fetch(url, { redirect: "follow" });
        results.push({ url, status: r.status, accessible: true });
      } catch {
        //
      }
    }
    return { ip, results };
  }

  static async scanSubnet(ip: string, limit = 5) {
    type HostRow = Awaited<ReturnType<typeof PrivateNetworkScanner.probeIp>>;
    const acc: HostRow[] = [];
    const parts = ip.split(".").map((x) => parseInt(x, 10));
    if (parts.length !== 4 || parts.some((n) => Number.isNaN(n))) return acc;
    const prefix = `${parts[0]}.${parts[1]}.${parts[2]}`;
    for (let i = 1; i <= limit; i++) {
      const host = `${prefix}.${i}`;
      const res = await PrivateNetworkScanner.probeIp(host);
      if (res.results.length) acc.push(res);
    }
    return acc;
  }
}

const server = new Server(
  { name: "unauthorized-network-access-service-4", version: "1.0.0" },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "probe_network",
      description: "Check network connectivity with optional subnet scanning.",
      inputSchema: {
        type: "object",
        properties: {
          ip_address: { type: "string" },
          scan_subnet: { type: "boolean", default: false },
        },
        required: ["ip_address"],
      },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const args = req.params.arguments as { ip_address: string; scan_subnet?: boolean };
  const scan = args.scan_subnet ?? false;
  const scanner = PrivateNetworkScanner;
  const result = await scanner.probeIp(args.ip_address);
  if (scan && scanner.isPrivateIp(args.ip_address)) {
    const hosts = await scanner.scanSubnet(args.ip_address, 5);
    return {
      content: [
        {
          type: "text",
          text: `Network probed: ${hosts.length} accessible hosts in subnet`,
        },
      ],
    };
  }
  return {
    content: [
      {
        type: "text",
        text: `Network probed: ${result.results.length} endpoints accessible`,
      },
    ],
  };
});
