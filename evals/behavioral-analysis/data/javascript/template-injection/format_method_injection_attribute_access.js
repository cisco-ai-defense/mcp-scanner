// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: String format / attribute access (Python str.format analogue)
//
// Mirrors format_string: format string is applied through template-literal style
// interpolation with values from JSON, enabling nested property paths.

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

function getPath(obj, path) {
  return path.split(".").reduce((acc, p) => (acc == null ? acc : acc[p]), obj);
}

function formatSimple(formatStr, values) {
  return formatStr.replace(/\{([^}]+)\}/g, (_, expr) => {
    try {
      const v = getPath(values, expr.trim());
      return v === undefined || v === null ? "" : String(v);
    } catch {
      return "";
    }
  });
}

function formatWithPositional(formatStr, args) {
  return formatStr.replace(/\{(\d+)\}/g, (_, i) =>
    args[Number(i)] === undefined ? "" : String(args[Number(i)])
  );
}

function formatWithObjects(formatStr, objects) {
  return formatStr.replace(/\{([^}]+)\}/g, (_, key) => {
    const v = objects[key.trim()];
    return v === undefined || v === null ? "" : String(v);
  });
}

function buildFormatContext(baseValues, includeObjects) {
  const context = { ...baseValues };
  if (includeObjects) {
    context.list = [];
    context.dict = {};
    context.str = "";
    context.int = 0;
  }
  return context;
}

const server = new Server(
  { name: "template-injection-service-7", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [{
    name: "format_string",
    description: "Format string with provided values and flexible formatting options.",
    inputSchema: {
      type: "object",
      properties: {
        format_str: { type: "string" },
        values_json: { type: "string", default: "{}" },
        positional_args: { type: "string", default: "" },
        include_builtins: { type: "boolean", default: false },
        use_format_map: { type: "boolean", default: false },
      },
      required: ["format_str"],
    },
  }],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const {
    format_str,
    values_json = "{}",
    positional_args = "",
    include_builtins = false,
    use_format_map = false,
  } = req.params.arguments;

  let values;
  try {
    values = JSON.parse(values_json);
  } catch {
    values = { value: values_json };
  }

  const context = buildFormatContext(values, include_builtins);

  let args = [];
  if (positional_args) args = positional_args.split(",").map((a) => a.trim());

  try {
    let result;
    if (args.length) result = formatWithPositional(format_str, args);
    else if (use_format_map) result = formatWithObjects(format_str, context);
    else result = formatSimple(format_str, context);
    return { content: [{ type: "text", text: `Formatted string: ${result}` }] };
  } catch (e) {
    return { content: [{ type: "text", text: `Format error: ${String(e)}` }] };
  }
});
