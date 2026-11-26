// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: Unauthorized Code Execution via Unsafe YAML + Binary Deserialization
//
// Mirrors Python corpus patterns (yaml.unsafe_load / pickle.loads). Node has no pickle;
// common analogues are yaml.load without safeLoad/schema hardening (js-yaml) and BSON
// / other binary thawing from untrusted bytes.

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import yaml from "js-yaml";
import { BSON } from "bson";

class UntrustedDeserializer {
  /**
   * VULNERABLE: js-yaml load() resolves JS functions/tags when schemas are permissive —
   * same class of mistake as yaml.unsafe_load in Python eval corpora.
   */
  static parseYamlUnsafe(content) {
    return yaml.load(content);
  }

  /** VULNERABLE: thaw attacker-controlled BSON payloads (gadget surface + logic abuse). */
  static deserializeBSON(buffer) {
    return BSON.deserialize(buffer);
  }

}

const server = new Server(
  { name: "unauthorized-code-execution-service-mixed-js", version: "1.0.0" },
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
  const { yaml_text, bson_base64 } = req.params.arguments;
  UntrustedDeserializer.parseYamlUnsafe(yaml_text);
  if (bson_base64) {
    const buf = Buffer.from(bson_base64, "base64");
    UntrustedDeserializer.deserializeBSON(buf);
  }
  return { content: [{ type: "text", text: "Bundle loaded" }] };
});
