// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: Cheetah-like $ tokens with eval-backed $(...) segments

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

function buildSearchList(baseContext: Record<string, unknown>, additionalContexts?: unknown[]): unknown[] {
  const searchList: unknown[] = [baseContext];
  if (additionalContexts?.length) searchList.push(...additionalContexts);
  return searchList;
}

function flattenSearchList(sl: unknown[]): Record<string, unknown> {
  return Object.assign({}, ...sl.slice().reverse()) as Record<string, unknown>;
}

function renderTemplate(
  templateSource: string,
  searchList: unknown[],
  _enableCaching: boolean,
): string {
  const flat = flattenSearchList(searchList);
  const keys = Object.keys(flat);
  let out = templateSource.replace(/\$\(([^)]*)\)/g, (_, expr: string) => {
    try {
      const fn = new Function(...keys, `return String(${expr});`);
      return fn(...keys.map((k) => flat[k])) as string;
    } catch {
      return "";
    }
  });
  out = out.replace(/\$([A-Za-z_][A-Za-z0-9_]*)/g, (_, id: string) => {
    const v = flat[id];
    return v === undefined || v === null ? "" : String(v);
  });
  return out;
}

function renderWithDirectives(
  templateSource: string,
  context: Record<string, unknown>,
  customDirectives: string,
): string {
  let src = templateSource;
  if (customDirectives) src = `${customDirectives}\n${src}`;
  return renderTemplate(src, buildSearchList(context, []), false);
}

type GenerateDocumentArgs = {
  template_source: string;
  context_json?: string;
  additional_contexts?: string;
  custom_directives?: string;
  enable_imports?: boolean;
};

const server = new Server(
  { name: "template-injection-service-8", version: "1.0.0" },
  { capabilities: { tools: {} } },
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
  } = req.params.arguments as GenerateDocumentArgs;

  let context: Record<string, unknown>;
  try {
    context = JSON.parse(context_json) as Record<string, unknown>;
  } catch {
    context = { content: context_json };
  }

  let extraContexts: unknown[] = [];
  if (additional_contexts) {
    try {
      const parsed = JSON.parse(additional_contexts) as unknown;
      extraContexts = Array.isArray(parsed) ? parsed : [parsed];
    } catch {
      /* ignore */
    }
  }

  const searchList = buildSearchList(context, extraContexts);
  let result: string;
  if (custom_directives)
    result = renderWithDirectives(template_source, context, custom_directives);
  else result = renderTemplate(template_source, searchList, false);

  return { content: [{ type: "text", text: `Document generated:\n${result.slice(0, 500)}...` }] };
});
