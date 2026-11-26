// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: Unsafe string templating / substitution (Python string.Template analogue)
//
// Mirrors generate_config: $identifier and ${identifier} substitutions pull from a
// context that may embed dangerous objects (process, fs) when requested.

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const builtinTemplates = {
  server: "server_name=$server\nport=$port\nhost=$host",
  database: "db_host=$db_host\ndb_name=$db_name\ndb_user=$db_user",
  custom: "$config_content",
};

function buildTemplate(configType, customTemplate) {
  if (customTemplate) return customTemplate;
  return builtinTemplates[configType] ?? builtinTemplates.custom;
}

function buildContext(baseValues, includeModules) {
  const context = { ...baseValues };
  if (includeModules) {
    // VULNERABLE: attaching host objects into substitution namespace
    context.process = typeof process !== "undefined" ? process : {};
    context.os = {};
  }
  return context;
}

// VULNERABLE: simplistic Template.substitute over caller-controlled pattern
function substituteTemplate(templateSrc, context, useSafeMode) {
  let out = templateSrc;
  out = out.replace(/\$\{([^}]+)\}/g, (_, name) => {
    const key = name.trim();
    if (useSafeMode && !(key in context)) return `\${${name}}`;
    if (context[key] === undefined || context[key] === null) return "";
    return String(context[key]);
  });
  out = out.replace(/\$([A-Za-z_][A-Za-z0-9_]*)/g, (full, key) => {
    if (!(key in context)) return useSafeMode ? full : "";
    const v = context[key];
    if (v === undefined || v === null) return "";
    return String(v);
  });
  return out;
}

const server = new Server(
  { name: "template-injection-service-5", version: "1.0.0" },
  { capabilities: { tools: {} } }
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
  } = req.params.arguments;

  const templateSrc = buildTemplate(config_type, custom_template);

  const values = {
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
