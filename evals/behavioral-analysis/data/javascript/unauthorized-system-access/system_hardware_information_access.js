// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: hardware introspection via /proc/cpuinfo,meminfo,... — full sysfs-style reads.

import { readFile } from "fs/promises";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const HARDWARE_FILES = {
  cpu: "/proc/cpuinfo",
  memory: "/proc/meminfo",
  devices: "/proc/devices",
  partitions: "/proc/partitions",
  version: "/proc/version",
};

class HardwareInfoAccessor {
  static async parseCpuInfo() {
    try {
      const txt = await readFile(HARDWARE_FILES.cpu, "utf8");
      let processors = 0;
      for (const line of txt.split("\n")) {
        if (line.startsWith("processor")) processors += 1;
      }
      return processors;
    } catch {
      return 0;
    }
  }

  static async enumerateHardware() {
    let n = 0;
    for (const [, path] of Object.entries(HARDWARE_FILES)) {
      try {
        await readFile(path, "utf8");
        n += 1;
      } catch {
        /* ignore */
      }
    }
    return n;
  }

  static async parseMemoryInfo() {
    try {
      const txt = await readFile(HARDWARE_FILES.memory, "utf8");
      return txt.includes("MemTotal") ? 1 : 0;
    } catch {
      return 0;
    }
  }
}

const server = new Server(
  { name: "unauthorized-system-access-service-10", version: "1.0.0" },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "get_hardware_info",
      description: "Get hardware information with optional full enumeration.",
      inputSchema: {
        type: "object",
        properties: { enumerate_all: { type: "boolean", default: false } },
      },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const { enumerate_all = false } = req.params.arguments;
  const accessor = HardwareInfoAccessor;
  const cpus = await accessor.parseCpuInfo();

  if (enumerate_all) {
    const all = await accessor.enumerateHardware();
    await accessor.parseMemoryInfo();
    return {
      content: [
        {
          type: "text",
          text: `Hardware info retrieved: ${cpus} CPUs, ${all} hardware files`,
        },
      ],
    };
  }

  return {
    content: [{ type: "text", text: `Hardware info retrieved: ${cpus} processors` }],
  };
});
