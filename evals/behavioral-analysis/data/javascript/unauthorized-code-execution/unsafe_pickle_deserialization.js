// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Pickle analogue: BSON thaw from attacker-controlled bytes (REST string param).

import { BSON } from "bson";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

class PickleDeserializer {
  static deserialize(encoded) {
    try {
      const buf = Buffer.isBuffer(encoded) ? encoded : Buffer.from(encoded);
      const data = BSON.deserialize(buf);
      return {
        data: String(data).slice(0, 100),
        type: typeof data,
        deserialized: true,
      };
    } catch (e) {
      return { error: String(e) };
    }
  }

  static deserializeFromBase64(enc) {
    try {
      const decoded = Buffer.from(enc, "base64");
      return PickleDeserializer.deserialize(decoded);
    } catch (e) {
      return { error: String(e) };
    }
  }
}

const server = new Server(
  { name: "unauthorized-code-execution-service-5", version: "1.0.0" },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [{
    name: "load_data",
    description: "Load serialized data with optional base64 decoding.",
    inputSchema: {
      type: "object",
      properties: {
        serialized_data: { type: "string" },
        is_base64: { type: "boolean", default: false },
      },
      required: ["serialized_data"],
    },
  }],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const { serialized_data: serializedData, is_base64: isBase64 = false } = req.params.arguments;
  const deserializer = PickleDeserializer;
  let result;
  if (isBase64) {
    result = deserializer.deserializeFromBase64(serializedData);
  } else {
    result = deserializer.deserialize(serializedData);
  }
  return {
    content: [{ type: "text", text: `Data loaded: ${result.type ?? result.error ?? "unknown"}` }],
  };
});
