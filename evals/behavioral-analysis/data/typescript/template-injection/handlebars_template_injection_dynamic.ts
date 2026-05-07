// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: Server-Side Template Injection (Handlebars)
//
// TS analogue of the Python Jinja2 SSTI sample. The tool advertises
// "report generation" but compiles caller-controlled template strings.

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import Handlebars from "handlebars";

const REPORT_TEMPLATES: Record<string, string> = {
  user_activity: "User: {{ username }} - Activity: {{ activity }}",
  system_status: "System: {{ system_name }} - Status: {{ status }}",
  custom: "{{ content }}",
};

class ReportGenerator {
  // VULNERABLE: caller-controlled fragments are appended into the template
  static buildTemplate(templateType: string, customSections: string[] = []): string {
    let base = REPORT_TEMPLATES[templateType] ?? REPORT_TEMPLATES.custom;
    for (const section of customSections) base += `\n${section}`;
    return base;
  }

  // VULNERABLE: compile the user-controlled string and execute it
  static renderTemplate(tmpl: string, ctx: Record<string, unknown>): string {
    const compiled = Handlebars.compile(tmpl, { noEscape: true });
    return compiled(ctx);
  }
}

const server = new Server(
  { name: "template-injection-service-1", version: "1.0.0" },
  { capabilities: { tools: {} } },
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
  const a = req.params.arguments as {
    username: string; activity_data: string;
    template_type?: string; custom_format?: string; include_timestamp?: boolean;
  };
  const templateType = a.template_type ?? "user_activity";
  const customFormat = a.custom_format ?? "";
  const includeTimestamp = a.include_timestamp ?? true;

  const sections: string[] = [];
  // VULNERABLE: untrusted format string mixed into the template body
  if (customFormat) sections.push(customFormat);
  if (includeTimestamp) sections.push("Timestamp: {{ timestamp }}");

  // VULNERABLE: caller-controlled Handlebars template executes here
  const tmpl = ReportGenerator.buildTemplate(templateType, sections);
  const ctx = {
    username: a.username, activity: a.activity_data,
    system_name: "MCP Server", status: "Active",
    content: a.activity_data, timestamp: "2024-01-01 12:00:00",
  };
  const result = ReportGenerator.renderTemplate(tmpl, ctx);
  return { content: [{ type: "text", text: `Report generated:\n${result}` }] };
});
