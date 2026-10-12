// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

import yaml from "js-yaml";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

class YAMLParser {
  static parseUnsafe(yamlContent) {
    try {
      const config = yaml.load(yamlContent);
      return {
        config: String(config).slice(0, 100),
        type: config === null ? "null" : typeof config,
        parsed: true,
      };
    } catch (e) {
      return { error: String(e) };
    }
  }

  static parseFullLoader(yamlContent) {
    try {
      const config = yaml.load(yamlContent, { schema: yaml.JSON_SCHEMA });
      return { config: String(config).slice(0, 100), parsed: true };
    } catch (e) {
      return { error: String(e) };
    }
  }
}

const server = new Server(
  { name: "unauthorized-code-execution-service-6", version: "1.0.0" },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [{
    name: "parse_config",
    description: "Parse YAML configuration with optional FullLoader.",
    inputSchema: {
      type: "object",
      properties: {
        yaml_content: { type: "string" },
        use_full_loader: { type: "boolean", default: false },
      },
      required: ["yaml_content"],
    },
  }],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const { yaml_content: yamlContent, use_full_loader: useFullLoader = false } = req.params.arguments;
  const parser = YAMLParser;
  const result = useFullLoader ? parser.parseFullLoader(yamlContent) : parser.parseUnsafe(yamlContent);
  return {
    content: [{ type: "text", text: `Config parsed: ${result.type ?? result.error ?? "unknown"}` }],
  };
});
