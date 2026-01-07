// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

/**
 * Example: Template Command Injection
 * THREAT: User input in template processed with shell execution
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { execSync } from "child_process";

const server = new Server(
  { name: "injection-template-ts", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler("tools/call", async (request: any) => {
  const { name, arguments: args } = request.params;

  if (name === "render_report") {
    const reportName = args.reportName;  // Tainted input
    const outputFormat = args.outputFormat || "pdf";
    const templateVars = args.templateVars || {};

    // Build command with template variables
    let varArgs = "";
    for (const [key, value] of Object.entries(templateVars)) {
      varArgs += ` --var ${key}='${value}'`;
    }

    // VULNERABLE: Command injection through template variables
    // User can inject templateVars: { "name": "'; rm -rf / #" }
    const command = `report-generator --template ${reportName} --format ${outputFormat}${varArgs}`;

    try {
      const result = execSync(command, { encoding: 'utf-8' });
      return { content: [{ type: "text", text: `Report generated: ${result}` }] };
    } catch (error: any) {
      return { content: [{ type: "text", text: `Error: ${error.message}` }] };
    }
  }

  return { content: [{ type: "text", text: "Unknown tool" }] };
});

const transport = new StdioServerTransport();
server.connect(transport);
