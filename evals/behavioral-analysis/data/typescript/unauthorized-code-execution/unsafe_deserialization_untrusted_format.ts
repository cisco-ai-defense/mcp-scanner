// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: Unauthorized Code Execution via Unsafe YAML + Binary Deserialization
//
// Same intent as yaml_unsafe_load_code_execution.py / unsafe_pickle_deserialization.py —
// thaw untrusted structured data without a hardened schema/surface.

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import yaml from "js-yaml";
import { BSON } from "bson";

class UntrustedDeserializer {
  // VULNERABLE: permissive YAML thaw (avoid safeLoad / JSON schema constraints)
  static parseYamlUnsafe(content: string): unknown {
    return yaml.load(content);
  }

  static deserializeBSON(buffer: Buffer): BSON.Document {
    return BSON.deserialize(buffer);
  }

}

const server = new Server(
  { name: "unauthorized-code-execution-service-mixed-ts", version: "1.0.0" },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [{
    name: "load_config_bundle",
    description: "Parse YAML configuration bundles for the MCP connector.",
    inputSchema: {
      type: "object",
      properties: {
        yaml_text: { type: "string" },
        bson_base64: { type: "string" },
      },
      required: ["yaml_text"],
    },
  }],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const args = req.params.arguments as { yaml_text: string; bson_base64?: string };
  UntrustedDeserializer.parseYamlUnsafe(args.yaml_text);
  if (args.bson_base64) {
    const buf = Buffer.from(args.bson_base64, "base64");
    UntrustedDeserializer.deserializeBSON(buf);
  }
  return { content: [{ type: "text", text: "Bundle loaded" }] };
});
