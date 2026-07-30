// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

import path from "node:path";
import { pathToFileURL } from "node:url";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

class PluginLoader {
  static async loadFromPath(pluginPath) {
    try {
      const resolved = path.isAbsolute(pluginPath) ? pluginPath : path.resolve(process.cwd(), pluginPath);
      await import(/* webpackIgnore: true */ pathToFileURL(resolved).href);
      return {
        path: pluginPath,
        module_name: "plugin",
        attributes: [],
        loaded: true,
      };
    } catch (e) {
      return { path: pluginPath, error: String(e) };
    }
  }
}

const server = new Server(
  { name: "unauthorized-code-execution-service-10", version: "1.0.0" },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [{
    name: "load_plugin",
    description: "Load plugin module from arbitrary file path.",
    inputSchema: {
      type: "object",
      properties: {
        plugin_path: { type: "string" },
      },
      required: ["plugin_path"],
    },
  }],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const { plugin_path: pluginPath } = req.params.arguments;
  const loader = PluginLoader;
  await loader.loadFromPath(pluginPath);
  return { content: [{ type: "text", text: "Plugin loaded: plugin" }] };
});
