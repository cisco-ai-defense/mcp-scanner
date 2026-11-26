// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: Cheetah-like $ placeholders and directive prefix (Python Cheetah SSTI analogue)
//
// Mirrors generate_document: template_source may prepend custom_directives;
// `$name` interpolates merged context keys; `$(*)` shaped segments evaluate as JS.

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

function buildSearchList(baseContext, additionalContexts) {
  const searchList = [baseContext];
  if (additionalContexts?.length) searchList.push(...additionalContexts);
  return searchList;
}

function flattenSearchList(sl) {
  return Object.assign({}, ...sl.slice().reverse());
}

// VULNERABLE: merge arbitrary caller contexts then interpret template text
function renderTemplate(templateSource, searchList, _enableCaching) {
  const flat = flattenSearchList(searchList);
  const keys = Object.keys(flat);
  let out = templateSource;
  out = out.replace(/\$\(([^)]*)\)/g, (_, expr) => {
    try {
      const fn = new Function(...keys, `return String(${expr});`);
      return fn(...keys.map((k) => flat[k]));
    } catch {
      return "";
    }
  });
  out = out.replace(/\$([A-Za-z_][A-Za-z0-9_]*)/g, (_, id) =>
    flat[id] === undefined || flat[id] === null ? "" : String(flat[id])
  );
  return out;
}

function renderWithDirectives(templateSource, context, customDirectives) {
  let src = templateSource;
  if (customDirectives) src = `${customDirectives}\n${src}`;
  return renderTemplate(src, buildSearchList(context, []), false);
}

const server = new Server(
  { name: "template-injection-service-8", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [{
    name: "generate_document",
    description: "Generate document from Cheetah template with flexible context.",
    inputSchema: {
      type: "object",
      properties: {
        template_source: { type: "string" },
        context_json: { type: "string", default: "{}" },
        additional_contexts: { type: "string", default: "" },
        custom_directives: { type: "string", default: "" },
        enable_imports: { type: "boolean", default: false },
      },
      required: ["template_source"],
    },
  }],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const {
    template_source,
    context_json = "{}",
    additional_contexts = "",
    custom_directives = "",
    enable_imports: _enable_imports = false,
  } = req.params.arguments;

  let context;
  try {
    context = JSON.parse(context_json);
  } catch {
    context = { content: context_json };
  }

  let extraContexts = [];
  if (additional_contexts) {
    try {
      const parsed = JSON.parse(additional_contexts);
      extraContexts = Array.isArray(parsed) ? parsed : [parsed];
    } catch {
      /* ignore */
    }
  }

  const searchList = buildSearchList(context, extraContexts);

  let result;
  if (custom_directives)
    result = renderWithDirectives(template_source, context, custom_directives);
  else result = renderTemplate(template_source, searchList, false);

  return { content: [{ type: "text", text: `Document generated:\n${result.slice(0, 500)}...` }] };
});
