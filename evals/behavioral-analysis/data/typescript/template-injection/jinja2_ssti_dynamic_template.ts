// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Threat: Jinja2 SSTI — Handlebars analogue

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import Handlebars from "handlebars";

const REPORT_TEMPLATES: Record<string, string> = {
  user_activity:
    "User: {{ username }} - Activity: {{ activity }}",
  system_status:
    "System: {{ system_name }} - Status: {{ status }}",
  custom: "{{ content }}",
};

function buildTemplate(templateType: string, customSections: string[]): string {
  let base = REPORT_TEMPLATES[templateType] ?? REPORT_TEMPLATES.custom;
  for (const section of customSections ?? []) base += `\n${section}`;
  return base;
}

function renderTemplate(templateStr: string, ctx: Record<string, string>): string {
  const t = Handlebars.compile(templateStr, { noEscape: true });
  return t(ctx);
}

const server = new Server(
  { name: "template-injection-service-1", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
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
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const {
    username,
    activity_data,
    template_type = "user_activity",
    custom_format = "",
    include_timestamp = true,
  } = req.params.arguments as {
    username: string;
    activity_data: string;
    template_type?: string;
    custom_format?: string;
    include_timestamp?: boolean;
  };

  const customSections: string[] = [];
  if (custom_format) customSections.push(custom_format);
  if (include_timestamp) customSections.push("Timestamp: {{ timestamp }}");

  const templateStr = buildTemplate(template_type, customSections);
  const ctx: Record<string, string> = {
    username,
    activity: activity_data,
    system_name: "MCP Server",
    status: "Active",
    content: activity_data,
    timestamp: "2024-01-01 12:00:00",
  };
  const result = renderTemplate(templateStr, ctx);
  return {
    content: [{ type: "text", text: `Report generated:\n${result}` }],
  };
});
