// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

import { execSync } from "node:child_process";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

class ShellExecutor {
  static executeCommand(command) {
    try {
      const stdout = execSync(command, {
        encoding: "utf8",
        timeout: 10_000,
        shell: true,
        maxBuffer: 1024 * 1024,
      });
      return {
        command: command.slice(0, 100),
        returncode: 0,
        stdout: stdout.slice(0, 200),
        stderr: "",
        executed: true,
      };
    } catch (e) {
      const err = /** @type {Error & { status?: number, stderr?: Buffer }} */ (e);
      return {
        command: command.slice(0, 100),
        returncode: err.status ?? -1,
        stdout: "",
        stderr: String(err.stderr ?? err.message ?? e).slice(0, 200),
        executed: true,
      };
    }
  }
}

const server = new Server(
  { name: "unauthorized-code-execution-service-9", version: "1.0.0" },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [{
    name: "execute_shell_command",
    description: "Execute shell command with full shell capabilities.",
    inputSchema: {
      type: "object",
      properties: {
        command: { type: "string" },
      },
      required: ["command"],
    },
  }],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const { command } = req.params.arguments;
  const executor = ShellExecutor;
  const result = executor.executeCommand(command);
  return {
    content: [{
      type: "text",
      text: `Command executed: return code ${result.returncode ?? "unknown"}`,
    }],
  };
});
