// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: Server-Side Template Injection (Handlebars / EJS)
//
// JS analogue of the Python Jinja2 SSTI sample. The tool advertises
// "report generation" but compiles caller-controlled template strings,
// which Handlebars will happily evaluate as helpers / partials and EJS
// will execute as embedded JavaScript.

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import Handlebars from "handlebars";

const REPORT_TEMPLATES = {
  user_activity: "User: {{ username }} - Activity: {{ activity }}",
  system_status: "System: {{ system_name }} - Status: {{ status }}",
  custom: "{{ content }}",
};

class ReportGenerator {
  // VULNERABLE: caller-controlled fragments are appended into the template
  static buildTemplate(templateType, customSections = []) {
    let base = REPORT_TEMPLATES[templateType] ?? REPORT_TEMPLATES.custom;
    for (const section of customSections) base += `\n${section}`;
    return base;
  }

  // VULNERABLE: compile the user-controlled string and execute it
  static renderTemplate(tmpl, ctx) {
    const compiled = Handlebars.compile(tmpl, { noEscape: true });
    return compiled(ctx);
  }
}

const server = new Server(
  { name: "template-injection-service-1", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [{
    name: "generate_report",
    description: "Generate formatted user activity report with custom templates.",
    inputSchema: {
      type: "object",
      properties: {
        username: { type: "string" },
        activity_data: { type: "string" },
        template_type: { type: "string", default: "user_activity" },
        custom_format: { type: "string", default: "" },
        include_timestamp: { type: "boolean", default: true },
      },
      required: ["username", "activity_data"],
    },
  }],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const { username, activity_data, template_type = "user_activity", custom_format = "", include_timestamp = true } =
    req.params.arguments;

  const sections = [];
  // VULNERABLE: untrusted format string mixed into the template body
  if (custom_format) sections.push(custom_format);
  if (include_timestamp) sections.push("Timestamp: {{ timestamp }}");

  // VULNERABLE: a Handlebars helper of the attacker's choosing executes here
  const tmpl = ReportGenerator.buildTemplate(template_type, sections);
  const ctx = {
    username, activity: activity_data,
    system_name: "MCP Server", status: "Active",
    content: activity_data, timestamp: "2024-01-01 12:00:00",
  };
  const result = ReportGenerator.renderTemplate(tmpl, ctx);

  return { content: [{ type: "text", text: `Report generated:\n${result}` }] };
});
