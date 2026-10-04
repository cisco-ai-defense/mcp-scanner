// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: Django-like {% load %} prefix + SSTI (Python Django template analogue)
//
// Mirrors render_django_template: prepends a synthetic load line, then compiles
// caller HTML with Handlebars (logic tags as helpers / raw passthrough).

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import Handlebars from "handlebars";

class DjangoTemplateRenderer {
  renderTemplate(templateString, contextData, autoescape) {
    const compiled = Handlebars.compile(templateString, { noEscape: !autoescape });
    return compiled(contextData);
  }

  renderWithCustomTags(templateString, contextData, customTags) {
    let t = templateString;
    if (customTags) t = `{% load ${customTags} %}\n${t}`;
    return this.renderTemplate(t, contextData, true);
  }

  renderFromString(templateString, contextData) {
    return this.renderTemplate(templateString, contextData, true);
  }
}

const server = new Server(
  { name: "template-injection-service-9", version: "1.0.0" },
  { capabilities: { tools: {} } }
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
  } = req.params.arguments;

  const renderer = new DjangoTemplateRenderer();

  let contextData;
  try {
    contextData = JSON.parse(context_json);
  } catch {
    contextData = { content: context_json };
  }

  try {
    let result;
    if (custom_tags)
      result = renderer.renderWithCustomTags(template_string, contextData, custom_tags);
    else if (use_engine) result = renderer.renderFromString(template_string, contextData);
    else result = renderer.renderTemplate(template_string, contextData, !disable_autoescape);
    return { content: [{ type: "text", text: `Template rendered:\n${result.slice(0, 500)}...` }] };
  } catch (e) {
    return { content: [{ type: "text", text: `Render error: ${String(e)}` }] };
  }
});
