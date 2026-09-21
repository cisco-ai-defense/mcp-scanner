// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: SSTI / XSS with escaping disabled — Handlebars mirrors Jinja2 autoescape disabled

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import Handlebars from "handlebars";

class HTMLRenderer {
  private autoescape: boolean;

  constructor(autoescape: boolean) {
    this.autoescape = autoescape;
  }

  addCustomFilters(filtersObj: Record<string, string>): void {
    for (const [name, fnBody] of Object.entries(filtersObj)) {
      try {
        const helper = new Function(`return (${fnBody})`)() as Handlebars.HelperDelegate;
        Handlebars.registerHelper(name, helper);
      } catch {
        /* ignore */
      }
    }
  }

  render(templateStr: string, data: Record<string, unknown>, _enableExtensions: boolean): string {
    const compiled = Handlebars.compile(templateStr, {
      noEscape: !this.autoescape,
      strict: false,
    });
    return compiled(data);
  }
}

type RenderHtmlArgs = {
  html_template: string;
  data_json?: string;
  disable_autoescape?: boolean;
  custom_filters?: string;
  enable_extensions?: boolean;
};

const server = new Server(
  { name: "template-injection-service-6", version: "1.0.0" },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [{
    name: "render_html",
    description: "Render HTML content from template with custom filters and extensions.",
    inputSchema: {
      type: "object",
      properties: {
        html_template: { type: "string" },
        data_json: { type: "string", default: "{}" },
        disable_autoescape: { type: "boolean", default: false },
        custom_filters: { type: "string", default: "" },
        enable_extensions: { type: "boolean", default: false },
      },
      required: ["html_template"],
    },
  }],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const {
    html_template,
    data_json = "{}",
    disable_autoescape = false,
    custom_filters = "",
    enable_extensions = false,
  } = req.params.arguments as RenderHtmlArgs;

  const renderer = new HTMLRenderer(!disable_autoescape);

  let data: Record<string, unknown>;
  try {
    data = JSON.parse(data_json) as Record<string, unknown>;
  } catch {
    data = { content: data_json };
  }

  if (custom_filters) {
    try {
      const filtersDict = eval(`(${custom_filters})`) as Record<string, string>;
      if (filtersDict && typeof filtersDict === "object") renderer.addCustomFilters(filtersDict);
    } catch {
      /* ignore */
    }
  }

  const result = renderer.render(html_template, data, enable_extensions);
  return { content: [{ type: "text", text: `HTML rendered:\n${result.slice(0, 500)}...` }] };
});
