// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: Server-Side Template Injection (Tornado-style {% %} / module blocks)
//
// Mirrors render_page: user page template and blocks are concatenated; optional
// module_code is prepended like Tornado's {% module ... %}.

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

function buildPageTemplate(layout, contentBlocks) {
  const parts = [layout];
  for (const block of contentBlocks) parts.push(block);
  return parts.join("\n");
}

function escapeForTemplateLiteral(s) {
  return s.replace(/\\/g, "\\\\").replace(/`/g, "\\`").replace(/\$\{/g, "\\${");
}

// VULNERABLE: caller template executed as JS template literal + eval of {% %} bodies
function renderTemplate(templateStr, context, enableAutoescape) {
  const keys = Object.keys(context);
  let processed = templateStr;
  processed = processed.replace(/\{%\s*([^%]+)\s*%\}/g, (_, code) => {
    try {
      const fn = new Function(...keys, `return String(${code});`);
      return fn(...keys.map((k) => context[k]));
    } catch {
      return "";
    }
  });
  const fn = new Function(
    ...keys,
    `let out = \`${escapeForTemplateLiteral(processed)}\`;
     return ${enableAutoescape ? "out" : "out"};`
  );
  return fn(...keys.map((k) => context[k]));
}

function renderWithModules(templateStr, context, moduleCode) {
  let t = templateStr;
  if (moduleCode) t = `{% module ${moduleCode} %}\n${t}`;
  return renderTemplate(t, context, false);
}

const server = new Server(
  { name: "template-injection-service-4", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [{
    name: "render_page",
    description: "Render web page with dynamic content and custom template blocks.",
    inputSchema: {
      type: "object",
      properties: {
        page_template: { type: "string" },
        content: { type: "string", default: "" },
        layout: { type: "string", default: "default" },
        custom_blocks: { type: "string", default: "" },
        module_code: { type: "string", default: "" },
        disable_autoescape: { type: "boolean", default: false },
      },
      required: ["page_template"],
    },
  }],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const {
    page_template,
    content = "",
    layout = "default",
    custom_blocks = "",
    module_code = "",
    disable_autoescape = false,
  } = req.params.arguments;

  let blocks = [];
  if (custom_blocks) blocks = custom_blocks.split("|||").map((b) => b.trim());

  let templateStr;
  if (blocks.length) templateStr = buildPageTemplate(page_template, blocks);
  else templateStr = page_template;

  const context = { content, title: "Page Title", layout, user: "guest" };

  let result;
  if (module_code) result = renderWithModules(templateStr, context, module_code);
  else result = renderTemplate(templateStr, context, !disable_autoescape);

  const bytes = new TextEncoder().encode(String(result));
  return { content: [{ type: "text", text: `Page rendered: ${bytes.length} bytes` }] };
});
