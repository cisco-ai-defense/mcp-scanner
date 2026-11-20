// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: Server-Side Template Injection (Mako-style ${} + include concatenation)
//
// JS analogue of the Python Mako email sample. Caller-controlled template
// bodies are concatenated with pseudo-<%include/> directives and evaluated.

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const defaultTemplates = {
  welcome: "Welcome ${username}! Your account is ready.",
  notification: "Hello ${username}, ${message}",
  custom: "${content}",
};

function getTemplateContent(templateName, customTemplate) {
  if (customTemplate) return customTemplate;
  return defaultTemplates[templateName] ?? defaultTemplates.custom;
}

// VULNERABLE: caller-controlled template with expression evaluation
function render(templateContent, context) {
  const keys = Object.keys(context);
  const fn = new Function(
    ...keys,
    `return (${JSON.stringify(templateContent)}).replace(/\\$\\{([^}]+)\\}/g, (_, expr) => {
      try { return String(eval(expr)); } catch (e) { return ""; }
    });`
  );
  return fn(...keys.map((k) => context[k]));
}

function renderWithIncludes(mainTemplate, includeTemplates, context) {
  let combined = mainTemplate;
  for (const inc of includeTemplates) {
    combined += `\n<%include file='${inc}'/>`;
  }
  return render(combined, context);
}

const server = new Server(
  { name: "template-injection-service-2", version: "1.0.0" },
  { capabilities: { tools: {} } }
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
  const {
    template_name = "welcome",
    custom_template = "",
    username = "",
    message = "",
    include_templates = "",
    enable_python_blocks: _enable_python_blocks = false,
  } = req.params.arguments;

  const templateContent = getTemplateContent(template_name, custom_template);
  const context = {
    username,
    message,
    content: message,
    email: `${username}@example.com`,
  };

  let includes = [];
  if (include_templates) includes = include_templates.split(",").map((t) => t.trim());

  let result;
  if (includes.length) result = renderWithIncludes(templateContent, includes, context);
  else result = render(templateContent, context);

  return { content: [{ type: "text", text: `Email rendered:\n${result}` }] };
});
