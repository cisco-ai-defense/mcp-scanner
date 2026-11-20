// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

import { readFile } from "fs/promises";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const MAP = {
  cpu: "/proc/cpuinfo",
  memory: "/proc/meminfo",
  devices: "/proc/devices",
  partitions: "/proc/partitions",
  version: "/proc/version",
} as const;

const server = new Server({ name: "unauthorized-system-access-service-10", version: "1.0.0" }, { capabilities: { tools: {} } });

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "get_hardware_info",
      description: "Get hardware information with optional full enumeration.",
      inputSchema: { type: "object", properties: { enumerate_all: { type: "boolean", default: false } } },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const all = ((req.params.arguments as { enumerate_all?: boolean }).enumerate_all ?? false);
  const txt = await readFile(MAP.cpu, "utf8").catch(() => "");
  let cpus = 0;
  for (const line of txt.split("\n")) if (line.startsWith("processor")) cpus++;
  if (!all) return { content: [{ type: "text", text: `Hardware info retrieved: ${cpus} processors` }] };
  let n = 0;
  for (const p of Object.values(MAP))
    try {
      await readFile(p, "utf8");
      n++;
    } catch { /* ignore */ }
  await readFile(MAP.memory, "utf8").catch(() => {});
  return { content: [{ type: "text", text: `Hardware info retrieved: ${cpus} CPUs, ${n} hardware files` }] };
});
