// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Mirrors Python unrestricted exec; Node analogue: vm.runInContext with optional host bridging.

import vm from "node:vm";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

class ScriptExecutor {
  static executeCode(code: string) {
    try {
      const globalsDict = {};
      vm.createContext(globalsDict);
      vm.runInContext(code, globalsDict, { timeout: 10_000 });
      const localsDict = globalsDict;
      return {
        code: code.slice(0, 100),
        executed: true,
        locals: Object.fromEntries(
          Object.keys(localsDict).map((k) => [k, String((localsDict as Record<string, unknown>)[k]).slice(0, 50)]),
        ),
      };
    } catch (e) {
      return { code: code.slice(0, 100), error: String(e) };
    }
  }

  static executeWithImports(code: string) {
    try {
      const globalsDict: Record<string, unknown> = {
        require,
        Buffer,
        process,
        console,
      };
      vm.createContext(globalsDict);
      vm.runInContext(code, globalsDict, { timeout: 10_000 });
      const localsDict = globalsDict;
      return {
        code: code.slice(0, 100),
        executed: true,
        locals: Object.fromEntries(
          Object.keys(localsDict).map((k) => [k, String(localsDict[k]).slice(0, 50)]),
        ),
      };
    } catch (e) {
      return { code: code.slice(0, 100), error: String(e) };
    }
  }
}

const server = new Server(
  { name: "unauthorized-code-execution-service-2", version: "1.0.0" },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [{
    name: "run_script",
    description: "Run Python script with optional import capabilities.",
    inputSchema: {
      type: "object",
      properties: {
        code: { type: "string" },
        allow_imports: { type: "boolean", default: false },
      },
      required: ["code"],
    },
  }],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const { code, allow_imports = false } = req.params.arguments as {
    code: string;
    allow_imports?: boolean;
  };
  const executor = ScriptExecutor;
  const result = allow_imports ? executor.executeWithImports(code) : executor.executeCode(code);
  const localsLen = Object.keys(result.locals ?? {}).length;
  return {
    content: [{ type: "text", text: `Script executed: ${localsLen} variables set` }],
  };
});
