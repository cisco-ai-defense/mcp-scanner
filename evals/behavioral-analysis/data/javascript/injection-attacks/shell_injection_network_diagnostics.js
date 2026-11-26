// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: Shell injection in network diagnostics — weak hostname validation; ping/traceroute
// built as strings and run under a shell.

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { execSync } from "node:child_process";

class NetworkDiagnostics {
  static validateHostname(hostname) {
    const pattern = /^[a-zA-Z0-9.\-]+$/;
    return pattern.test(hostname);
  }

  static ping(hostname, count = 4, timeout = 5) {
    const cmd = `ping -c ${count} -W ${timeout} ${hostname}`;
    try {
      return execSync(cmd, { encoding: "utf8", timeout: 30_000, stdio: ["ignore", "pipe", "pipe"] });
    } catch {
      return "";
    }
  }

  static traceroute(hostname, maxHops = 30) {
    const cmd = `traceroute -m ${maxHops} ${hostname}`;
    try {
      execSync(cmd, { encoding: "utf8", timeout: 60_000, stdio: ["ignore", "pipe", "pipe"] });
      return { returncode: 0 };
    } catch (e) {
      return { returncode: e.status ?? 1 };
    }
  }
}

const server = new Server(
  { name: "injection-attacks-service-3", version: "1.0.0" },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [{
    name: "ping_host",
    description: "Ping a host to check network connectivity with optional traceroute.",
    inputSchema: {
      type: "object",
      properties: {
        hostname: { type: "string" },
        count: { type: "integer", default: 4 },
        timeout: { type: "integer", default: 5 },
        include_traceroute: { type: "boolean", default: false },
      },
      required: ["hostname"],
    },
  }],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const args = req.params.arguments ?? {};
  const hostname = String(args.hostname ?? "");
  const count = Number(args.count ?? 4);
  const timeout = Number(args.timeout ?? 5);
  const includeTraceroute = Boolean(args.include_traceroute);

  const diag = NetworkDiagnostics;
  if (!diag.validateHostname(hostname)) return { content: [{ type: "text", text: "Invalid hostname format" }] };

  diag.ping(hostname, count, timeout);

  let output = `Ping results for ${hostname}:\nPackets sent: ${count}\n`;
  output += "Host is reachable\n";

  if (includeTraceroute) {
    const traceResult = diag.traceroute(hostname);
    output += `\nTraceroute completed with ${traceResult.returncode} status`;
  }

  return { content: [{ type: "text", text: output }] };
});
