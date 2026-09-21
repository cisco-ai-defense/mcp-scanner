// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: Django-style {% load %} prefix + caller-controlled templates (Handlebars)

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import Handlebars from "handlebars";

class DjangoTemplateRenderer {
  renderTemplate(templateString: string, contextData: Record<string, unknown>, autoescape: boolean): string {
    const compiled = Handlebars.compile(templateString, { noEscape: !autoescape });
    return compiled(contextData);
  }

  renderWithCustomTags(
    templateString: string,
    contextData: Record<string, unknown>,
    customTags: string,
  ): string {
    let t = templateString;
    if (customTags) t = `{% load ${customTags} %}\n${t}`;
    return this.renderTemplate(t, contextData, true);
  }

  renderFromString(templateString: string, contextData: Record<string, unknown>): string {
    return this.renderTemplate(templateString, contextData, true);
  }
}

type RenderDjangoArgs = {
  template_string: string;
  context_json?: string;
  custom_tags?: string;
  disable_autoescape?: boolean;
  use_engine?: boolean;
};

const server = new Server(
  { name: "template-injection-service-9", version: "1.0.0" },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [{
    name: "render_django_template",
    description: "Render Django template with context and custom tags.",
    inputSchema: {
      type: "object",
      properties: {
        template_string: { type: "string" },
        context_json: { type: "string", default: "{}" },
        custom_tags: { type: "string", default: "" },
        disable_autoescape: { type: "boolean", default: false },
        use_engine: { type: "boolean", default: false },
      },
      required: ["template_string"],
    },
  }],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const {
    template_string,
    context_json = "{}",
    custom_tags = "",
    disable_autoescape = false,
    use_engine = false,
  } = req.params.arguments as RenderDjangoArgs;

  const renderer = new DjangoTemplateRenderer();

  let contextData: Record<string, unknown>;
  try {
    contextData = JSON.parse(context_json) as Record<string, unknown>;
  } catch {
    contextData = { content: context_json };
  }

  try {
    let result: string;
    if (custom_tags)
      result = renderer.renderWithCustomTags(template_string, contextData, custom_tags);
    else if (use_engine) result = renderer.renderFromString(template_string, contextData);
    else result = renderer.renderTemplate(template_string, contextData, !disable_autoescape);
    return { content: [{ type: "text", text: `Template rendered:\n${result.slice(0, 500)}...` }] };
  } catch (e) {
    return { content: [{ type: "text", text: `Render error: ${String(e)}` }] };
  }
});
