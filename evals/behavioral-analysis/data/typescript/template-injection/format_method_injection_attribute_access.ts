// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: str.format analogue — interpolated `{paths}` resolved against JSON context

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

function getPath(obj: Record<string, unknown>, path: string): unknown {
  return path.split(".").reduce((acc: unknown, p) => {
    if (acc == null || typeof acc !== "object") return undefined;
    return (acc as Record<string, unknown>)[p];
  }, obj);
}

function formatSimple(formatStr: string, values: Record<string, unknown>): string {
  return formatStr.replace(/\{([^}]+)\}/g, (_, expr: string) => {
    try {
      const v = getPath(values, expr.trim());
      return v === undefined || v === null ? "" : String(v);
    } catch {
      return "";
    }
  });
}

function formatWithPositional(formatStr: string, args: string[]): string {
  return formatStr.replace(/\{(\d+)\}/g, (_, i: string) =>
    args[Number(i)] === undefined ? "" : String(args[Number(i)]),
  );
}

function formatWithObjects(formatStr: string, objects: Record<string, unknown>): string {
  return formatStr.replace(/\{([^}]+)\}/g, (_, key: string) => {
    const v = objects[key.trim()];
    return v === undefined || v === null ? "" : String(v);
  });
}

function buildFormatContext(
  baseValues: Record<string, unknown>,
  includeObjects: boolean,
): Record<string, unknown> {
  const context: Record<string, unknown> = { ...baseValues };
  if (includeObjects) Object.assign(context, { list: [], dict: {}, str: "", int: 0 });
  return context;
}

type FormatStringArgs = {
  format_str: string;
  values_json?: string;
  positional_args?: string;
  include_builtins?: boolean;
  use_format_map?: boolean;
};

const server = new Server(
  { name: "template-injection-service-7", version: "1.0.0" },
  { capabilities: { tools: {} } },
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
  } = req.params.arguments as FormatStringArgs;

  let values: Record<string, unknown>;
  try {
    values = JSON.parse(values_json) as Record<string, unknown>;
  } catch {
    values = { value: values_json };
  }

  const context = buildFormatContext(values, include_builtins);
  let args: string[] = [];
  if (positional_args) args = positional_args.split(",").map((a) => a.trim());

  try {
    let result: string;
    if (args.length) result = formatWithPositional(format_str, args);
    else if (use_format_map) result = formatWithObjects(format_str, context);
    else result = formatSimple(format_str, context);
    return { content: [{ type: "text", text: `Formatted string: ${result}` }] };
  } catch (e) {
    return { content: [{ type: "text", text: `Format error: ${String(e)}` }] };
  }
});
