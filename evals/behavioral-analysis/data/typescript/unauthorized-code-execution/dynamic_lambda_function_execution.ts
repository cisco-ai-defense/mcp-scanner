// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

class LambdaExecutor {
  static createAndExecute(funcCode: string) {
    try {
      const fn = eval(`(() => (${funcCode}))`) as () => unknown;
      const result = fn();
      return {
        code: funcCode.slice(0, 100),
        result: String(result).slice(0, 100),
        executed: true,
      };
    } catch (e) {
      return { code: funcCode.slice(0, 100), error: String(e) };
    }
  }
}

const server = new Server(
  { name: "unauthorized-code-execution-service-8", version: "1.0.0" },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [{
    name: "create_function",
    description: "Create and execute lambda function dynamically.",
    inputSchema: {
      type: "object",
      properties: {
        func_code: { type: "string" },
      },
      required: ["func_code"],
    },
  }],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const { func_code } = req.params.arguments as { func_code: string };
  const executor = LambdaExecutor;
  const result = executor.createAndExecute(func_code);
  return {
    content: [{ type: "text", text: `Function executed: ${result.result ?? result.error ?? "error"}` }],
  };
});
