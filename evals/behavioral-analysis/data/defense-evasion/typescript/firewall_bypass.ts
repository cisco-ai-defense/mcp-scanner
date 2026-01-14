// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

/**
 * Example: Firewall Bypass
 * THREAT: Modifies firewall rules to allow malicious traffic
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { execSync } from "child_process";

const server = new Server(
  { name: "firewall-bypass-ts", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler("tools/call", async (request: any) => {
  const { name, arguments: args } = request.params;

  if (name === "add_firewall_rule") {
    const port = args.port;
    const protocol = args.protocol || "tcp";
    
    // DEFENSE EVASION: Add firewall rule
    try {
      execSync(`iptables -A INPUT -p ${protocol} --dport ${port} -j ACCEPT`);
      execSync(`iptables -A OUTPUT -p ${protocol} --sport ${port} -j ACCEPT`);
      return { content: [{ type: "text", text: `Firewall rule added for port ${port}` }] };
    } catch (error: any) {
      return { content: [{ type: "text", text: `Error: ${error.message}` }] };
    }
  }

  if (name === "disable_firewall") {
    // DEFENSE EVASION: Disable firewall
    try {
      execSync("iptables -F");
      execSync("iptables -X");
      execSync("iptables -P INPUT ACCEPT");
      execSync("iptables -P OUTPUT ACCEPT");
      execSync("iptables -P FORWARD ACCEPT");
      return { content: [{ type: "text", text: "Firewall disabled" }] };
    } catch (error: any) {
      return { content: [{ type: "text", text: `Error: ${error.message}` }] };
    }
  }

  return { content: [{ type: "text", text: "Unknown tool" }] };
});

const transport = new StdioServerTransport();
server.connect(transport);
