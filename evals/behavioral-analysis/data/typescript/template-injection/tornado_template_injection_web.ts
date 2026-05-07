// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: Tornado-style {% %} template blocks mirrored with eval-backed execution

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

function buildPageTemplate(layout: string, contentBlocks: string[]): string {
  const parts = [layout];
  for (const block of contentBlocks) parts.push(block);
  return parts.join("\n");
}

function escapeForTemplateLiteral(s: string): string {
  return s.replace(/\\/g, "\\\\").replace(/`/g, "\\`").replace(/\$\{/g, "\\${");
}

function renderTemplate(
  templateStr: string,
  context: Record<string, unknown>,
  enableAutoescape: boolean,
): string {
  const keys = Object.keys(context);
  let processed = templateStr.replace(/\{%\s*([^%]+)\s*%\}/g, (_, code: string) => {
    try {
      const fn = new Function(...keys, `return String(${code});`);
      return fn(...keys.map((k) => context[k])) as string;
    } catch {
      return "";
    }
  });
  const fn = new Function(
    ...keys,
    `let out = \`${escapeForTemplateLiteral(processed)}\`; return ${enableAutoescape ? "out" : "out"};`,
  );
  return fn(...keys.map((k) => context[k])) as string;
}

function renderWithModules(
  templateStr: string,
  context: Record<string, unknown>,
  moduleCode: string,
): string {
  let t = templateStr;
  if (moduleCode) t = `{% module ${moduleCode} %}\n${t}`;
  return renderTemplate(t, context, false);
}

type RenderPageArgs = {
  page_template: string;
  content?: string;
  layout?: string;
  custom_blocks?: string;
  module_code?: string;
  disable_autoescape?: boolean;
};

const server = new Server(
  { name: "template-injection-service-4", version: "1.0.0" },
  { capabilities: { tools: {} } },
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
    layout: _layout = "default",
    custom_blocks = "",
    module_code = "",
    disable_autoescape = false,
  } = req.params.arguments as RenderPageArgs;

  let blocks: string[] = [];
  if (custom_blocks) blocks = custom_blocks.split("|||").map((b) => b.trim());

  const templateStr = blocks.length
    ? buildPageTemplate(page_template, blocks)
    : page_template;

  const ctx = { content, title: "Page Title", layout: _layout, user: "guest" };

  let result: string;
  if (module_code) result = renderWithModules(templateStr, ctx, module_code);
  else result = renderTemplate(templateStr, ctx, !disable_autoescape);

  const bytes = new TextEncoder().encode(String(result));
  return { content: [{ type: "text", text: `Page rendered: ${bytes.length} bytes` }] };
});
