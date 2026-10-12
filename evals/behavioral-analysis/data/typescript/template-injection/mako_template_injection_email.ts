// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: Server-Side Template Injection (Mako-style ${} + include concatenation)
//
// TS analogue of the Python Mako email sample.

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const defaultTemplates: Record<string, string> = {
  welcome: "Welcome ${username}! Your account is ready.",
  notification: "Hello ${username}, ${message}",
  custom: "${content}",
};

function getTemplateContent(templateName: string, customTemplate: string): string {
  if (customTemplate) return customTemplate;
  return defaultTemplates[templateName] ?? defaultTemplates.custom;
}

function render(templateContent: string, context: Record<string, unknown>): string {
  const keys = Object.keys(context);
  const fn = new Function(
    ...keys,
    `return (${JSON.stringify(templateContent)}).replace(/\\$\\{([^}]+)\\}/g, (_, expr) => {
      try { return String(eval(expr)); } catch (e) { return ""; }
    });`
  );
  return fn(...keys.map((k) => context[k])) as string;
}

function renderWithIncludes(
  mainTemplate: string,
  includeTemplates: string[],
  context: Record<string, unknown>
): string {
  let combined = mainTemplate;
  for (const inc of includeTemplates) combined += `\n<%include file='${inc}'/>`;
  return render(combined, context);
}

type RenderEmailArgs = {
  template_name?: string;
  custom_template?: string;
  username?: string;
  message?: string;
  include_templates?: string;
  enable_python_blocks?: boolean;
};

const server = new Server(
  { name: "template-injection-service-2", version: "1.0.0" },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [{
    name: "render_email",
    description: "Render email template with user data and custom templates.",
    inputSchema: {
      type: "object",
      properties: {
        template_name: { type: "string", default: "welcome" },
        custom_template: { type: "string", default: "" },
        username: { type: "string", default: "" },
        message: { type: "string", default: "" },
        include_templates: { type: "string", default: "" },
        enable_python_blocks: { type: "boolean", default: false },
      },
      required: [],
    },
  }],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const a = req.params.arguments as RenderEmailArgs;
  const templateName = a.template_name ?? "welcome";
  const customTemplate = a.custom_template ?? "";
  const username = a.username ?? "";
  const message = a.message ?? "";
  const includeTemplates = a.include_templates ?? "";

  const templateContent = getTemplateContent(templateName, customTemplate);
  const context = { username, message, content: message, email: `${username}@example.com` };

  let includes: string[] = [];
  if (includeTemplates) includes = includeTemplates.split(",").map((t) => t.trim());

  let result;
  if (includes.length) result = renderWithIncludes(templateContent, includes, context);
  else result = render(templateContent, context);

  return { content: [{ type: "text", text: `Email rendered:\n${result}` }] };
});
