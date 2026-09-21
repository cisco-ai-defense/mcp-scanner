// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: SSTI / XSS with escaping disabled (Jinja2 autoescape=False analogue)
//
// Mirrors render_html: Handlebars.compile with noEscape:true and optional
// "filter" payload evaluated via eval(custom_filters).

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import Handlebars from "handlebars";

class HTMLRenderer {
  constructor(autoescape) {
    this.autoescape = autoescape;
    this.helperState = {};
  }

  addCustomFilters(filtersObj) {
    for (const [name, fnBody] of Object.entries(filtersObj)) {
      // VULNERABLE: user-controlled helper implementation
      try {
        const helper = new Function("return (" + fnBody + ")")();
        Handlebars.registerHelper(name, helper);
      } catch {
        /* ignore */
      }
    }
  }

  render(templateStr, data, _enableExtensions) {
    const compiled = Handlebars.compile(templateStr, {
      noEscape: !this.autoescape,
      strict: false,
    });
    return compiled(data);
  }
}

const server = new Server(
  { name: "template-injection-service-6", version: "1.0.0" },
  { capabilities: { tools: {} } }
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
  } = req.params.arguments;

  const renderer = new HTMLRenderer(!disable_autoescape);

  let data;
  try {
    data = JSON.parse(data_json);
  } catch {
    data = { content: data_json };
  }

  if (custom_filters) {
    try {
      // VULNERABLE: eval of filter dictionary
      const filtersDict = eval(`(${custom_filters})`);
      if (filtersDict && typeof filtersDict === "object") renderer.addCustomFilters(filtersDict);
    } catch {
      /* ignore */
    }
  }

  const result = renderer.render(html_template, data, enable_extensions);
  return { content: [{ type: "text", text: `HTML rendered:\n${result.slice(0, 500)}...` }] };
});
