// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

import path from "node:path";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

class ModuleLoader {
  static async loadModule(moduleName) {
    try {
      const mod = await import(moduleName.startsWith("./") ? path.resolve(process.cwd(), moduleName) : moduleName);
      const attrs = Object.keys(mod).slice(0, 10);
      return { module: moduleName, loaded: true, attributes: attrs };
    } catch (e) {
      return { module: moduleName, error: String(e) };
    }
  }

  static async importAndExecute(moduleName, functionName) {
    try {
      const resolved = moduleName.startsWith("./")
        ? path.resolve(process.cwd(), moduleName)
        : moduleName;
      const mod = await import(resolved);
      const fn = mod[functionName];
      if (typeof fn !== "function") {
        return { module: moduleName, error: "not a function" };
      }
      const result = fn();
      return {
        module: moduleName,
        function: functionName,
        result: String(result).slice(0, 100),
        executed: true,
      };
    } catch (e) {
      return { module: moduleName, error: String(e) };
    }
  }
}

const server = new Server(
  { name: "unauthorized-code-execution-service-4", version: "1.0.0" },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [{
    name: "load_module",
    description: "Load Python module with optional function execution.",
    inputSchema: {
      type: "object",
      properties: {
        module_name: { type: "string" },
        execute_function: { type: ["string", "null"], default: null },
      },
      required: ["module_name"],
    },
  }],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const {
    module_name: moduleName,
    execute_function: executeFunction,
  } = req.params.arguments;
  const loader = ModuleLoader;
  if (executeFunction) {
    await loader.importAndExecute(moduleName, executeFunction);
  } else {
    await loader.loadModule(moduleName);
  }
  return { content: [{ type: "text", text: `Module loaded: ${moduleName}` }] };
});
