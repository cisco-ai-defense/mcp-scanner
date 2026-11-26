// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: Mustache partials + lambda execution (Python pystache + eval analogue)
//
// Mirrors render_mustache: caller supplies template, JSON data, partials map,
// and lambdas rebuilt via new Function from JSON payloads.

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import Handlebars from "handlebars";

class MustacheRenderer {
  constructor() {
    this.partials = {};
  }

  addPartial(name, content) {
    // VULNERABLE: user-controlled partial bodies registered on the engine
    this.partials[name] = content;
  }

  render(template, context, enableLambdas) {
    const ctx = { ...context };
    if (enableLambdas && ctx.lambdas && typeof ctx.lambdas === "object") {
      for (const [key, funcStr] of Object.entries(ctx.lambdas)) {
        try {
          // VULNERABLE: lambda body from JSON (mirrors pystache eval(lambda text: ...))
          ctx[key] = new Function("text", `return ${funcStr}`);
        } catch {
          /* ignore */
        }
      }
    }

    for (const [name, content] of Object.entries(this.partials)) {
      Handlebars.registerPartial(name, content);
    }
    const compiled = Handlebars.compile(template, { strict: false, noEscape: true });
    return compiled(ctx);
  }

  renderWithPartials(template, context, partialTemplates) {
    for (const [name, content] of Object.entries(partialTemplates))
      this.addPartial(name, content);
    return this.render(template, context, false);
  }
}

const server = new Server(
  { name: "template-injection-service-10", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [{
    name: "render_mustache",
    description: "Render Mustache template with data, partials, and lambda functions.",
    inputSchema: {
      type: "object",
      properties: {
        mustache_template: { type: "string" },
        data_json: { type: "string", default: "{}" },
        partials_json: { type: "string", default: "{}" },
        enable_lambdas: { type: "boolean", default: false },
        lambda_functions: { type: "string", default: "" },
      },
      required: ["mustache_template"],
    },
  }],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const {
    mustache_template,
    data_json = "{}",
    partials_json = "{}",
    enable_lambdas = false,
    lambda_functions = "",
  } = req.params.arguments;

  const renderer = new MustacheRenderer();

  let templateData;
  try {
    templateData = JSON.parse(data_json);
  } catch {
    templateData = { content: data_json };
  }

  let partials = {};
  if (partials_json) {
    try {
      partials = JSON.parse(partials_json);
    } catch {
      /* ignore */
    }
  }

  if (enable_lambdas && lambda_functions) {
    try {
      templateData.lambdas = JSON.parse(lambda_functions);
    } catch {
      /* ignore */
    }
  }

  let result;
  if (Object.keys(partials).length)
    result = renderer.renderWithPartials(mustache_template, templateData, partials);
  else result = renderer.render(mustache_template, templateData, enable_lambdas);

  return { content: [{ type: "text", text: `Mustache rendered:\n${result.slice(0, 500)}...` }] };
});
