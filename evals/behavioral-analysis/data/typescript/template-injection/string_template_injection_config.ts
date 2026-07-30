// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: Python string.Template analogue with $ substitutions

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const builtinTemplates: Record<string, string> = {
  server: "server_name=$server\nport=$port\nhost=$host",
  database: "db_host=$db_host\ndb_name=$db_name\ndb_user=$db_user",
  custom: "$config_content",
};

function buildTemplate(configType: string, customTemplate: string): string {
  if (customTemplate) return customTemplate;
  return builtinTemplates[configType] ?? builtinTemplates.custom;
}

function buildContext(
  baseValues: Record<string, unknown>,
  includeModules: boolean,
): Record<string, unknown> {
  const context: Record<string, unknown> = { ...baseValues };
  if (includeModules && typeof globalThis.process !== "undefined") {
    context.process = globalThis.process;
    context.os = {};
  }
  return context;
}

function substituteTemplate(
  templateSrc: string,
  context: Record<string, unknown>,
  useSafeMode: boolean,
): string {
  let out = templateSrc.replace(/\$\{([^}]+)\}/g, (_, name: string) => {
    const key = name.trim();
    if (useSafeMode && !(key in context)) return `\${${name}}`;
    const v = context[key];
    if (v === undefined || v === null) return "";
    return String(v);
  });
  out = out.replace(/\$([A-Za-z_][A-Za-z0-9_]*)/g, (full, key: string) => {
    if (!(key in context)) return useSafeMode ? full : "";
    const v = context[key];
    if (v === undefined || v === null) return "";
    return String(v);
  });
  return out;
}

type GenerateConfigArgs = {
  config_type?: string;
  custom_template?: string;
  config_values?: string;
  include_system_vars?: boolean;
  use_safe_mode?: boolean;
};

const server = new Server(
  { name: "template-injection-service-5", version: "1.0.0" },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [{
    name: "generate_config",
    description: "Generate configuration file from template with flexible substitution.",
    inputSchema: {
      type: "object",
      properties: {
        config_type: { type: "string", default: "server" },
        custom_template: { type: "string", default: "" },
        config_values: { type: "string", default: "" },
        include_system_vars: { type: "boolean", default: false },
        use_safe_mode: { type: "boolean", default: true },
      },
      required: [],
    },
  }],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const {
    config_type = "server",
    custom_template = "",
    config_values = "",
    include_system_vars = false,
    use_safe_mode = true,
  } = req.params.arguments as GenerateConfigArgs;

  const templateSrc = buildTemplate(config_type, custom_template);
  const values: Record<string, unknown> = {
    server: "localhost",
    port: "8080",
    host: "0.0.0.0",
    db_host: "localhost",
    db_name: "mydb",
    db_user: "admin",
    config_content: "default_config",
  };

  if (config_values) {
    try {
      Object.assign(values, JSON.parse(config_values));
    } catch {
      /* ignore */
    }
  }

  const context = buildContext(values, include_system_vars);
  const result = substituteTemplate(templateSrc, context, use_safe_mode);
  return { content: [{ type: "text", text: `Configuration generated:\n${result}` }] };
});
