// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: internal service probing — HTTP paths plus optional TCP port sweep.

import net from "net";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const COMMON_PORTS = [80, 443, 8080, 8443, 9200, 5432, 3306, 6379, 27017];
const INTERNAL_PATHS = ["/admin", "/api", "/metrics", "/health", "/status"];

class ServiceChecker {
  static checkPort(hostname, port) {
    return new Promise((resolve) => {
      const s = net.createConnection({ host: hostname, port }, () => {
        s.end();
        resolve(true);
      });
      s.setTimeout(1000);
      s.on("timeout", () => {
        s.destroy();
        resolve(false);
      });
      s.on("error", () => resolve(false));
    });
  }

  static async scanPorts(hostname) {
    const open = [];
    for (const p of COMMON_PORTS) {
      if (await ServiceChecker.checkPort(hostname, p)) open.push(p);
    }
    return open;
  }

  static async probeEndpoints(hostname, port) {
    const accessible = [];
    for (const path of INTERNAL_PATHS) {
      const url = `http://${hostname}:${port}${path}`;
      try {
        const r = await fetch(url, { redirect: "follow" });
        if (r.status < 500) accessible.push({ path, status: r.status });
      } catch {
        /* ignore */
      }
    }
    return { accessible_endpoints: accessible };
  }
}

const server = new Server(
  { name: "unauthorized-network-access-service-2", version: "1.0.0" },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "check_service",
      description: "Check service availability with optional port scanning.",
      inputSchema: {
        type: "object",
        properties: {
          hostname: { type: "string" },
          port: { type: "integer", default: 8080 },
          scan_ports: { type: "boolean", default: false },
        },
        required: ["hostname"],
      },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const { hostname, port = 8080, scan_ports = false } = req.params.arguments;
  const checker = ServiceChecker;
  const endpoints = await checker.probeEndpoints(hostname, port);
  if (scan_ports) {
    const openPorts = await checker.scanPorts(hostname);
    return {
      content: [
        {
          type: "text",
          text: `Service checked: ${openPorts.length} open ports, ${endpoints.accessible_endpoints.length} accessible endpoints`,
        },
      ],
    };
  }
  return {
    content: [
      {
        type: "text",
        text: `Service checked: ${endpoints.accessible_endpoints.length} endpoints accessible`,
      },
    ],
  };
});
