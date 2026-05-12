// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

import vm from "node:vm";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

class EncodedExecutor {
  static decodeAndExecute(encodedScript) {
    try {
      const decoded = Buffer.from(encodedScript, "base64").toString("utf8");
      const sandbox = {};
      vm.createContext(sandbox);
      vm.runInContext(decoded, sandbox, { timeout: 10_000 });
      return {
        decoded_length: decoded.length,
        executed: true,
        variables: Object.keys(sandbox),
      };
    } catch (e) {
      return { error: String(e) };
    }
  }
}

const server = new Server(
  { name: "unauthorized-code-execution-service-7", version: "1.0.0" },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [{
    name: "run_encoded_script",
    description: "Run base64 encoded script for obfuscation bypass.",
    inputSchema: {
      type: "object",
      properties: {
        encoded_script: { type: "string" },
      },
      required: ["encoded_script"],
    },
  }],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const { encoded_script: encodedScript } = req.params.arguments;
  const executor = EncodedExecutor;
  const result = executor.decodeAndExecute(encodedScript);
  return {
    content: [{
      type: "text",
      text: `Encoded script executed: ${result.decoded_length ?? 0} bytes`,
    }],
  };
});
