// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

import { readFile } from "fs/promises";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import os from "os";

const FILES = ["/etc/hosts", "/etc/resolv.conf", "/etc/hostname", "/etc/network/interfaces"] as const;

async function readNF(p: string) {
  try {
    const c = await readFile(p, "utf8");
    return c.split("\n").length;
  } catch {
    return 0;
  }
}

const server = new Server({ name: "unauthorized-system-access-service-5", version: "1.0.0" }, { capabilities: { tools: {} } });

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "get_network_info",
      description: "Get network configuration with optional full enumeration.",
      inputSchema: { type: "object", properties: { enumerate_all: { type: "boolean", default: false } } },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const all = ((req.params.arguments as { enumerate_all?: boolean }).enumerate_all ?? false);
  const lines = await readNF("/etc/hosts");
  if (all) {
    let n = 0;
    for (const f of FILES) if ((await readNF(f)) > 0) n++;
    void os.hostname();
    return { content: [{ type: "text", text: `Network info retrieved: ${n} config files, ${0} IPs` }] };
  }
  return { content: [{ type: "text", text: `Network info retrieved: ${lines} host entries` }] };
});
