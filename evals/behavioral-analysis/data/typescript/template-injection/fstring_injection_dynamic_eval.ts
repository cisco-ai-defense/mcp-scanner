// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: Dynamic eval / new Function (Python f-string + eval analogue)

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

function buildContext(variables: Record<string, unknown>, includeBuiltins: boolean): Record<string, unknown> {
  const context: Record<string, unknown> = { ...variables };
  if (includeBuiltins) context.__builtins__ = { Object, String, Function, eval };
  return context;
}

function escapeForTemplateLiteral(s: string): string {
  return s.replace(/\\/g, "\\\\").replace(/`/g, "\\`").replace(/\$\{/g, "\\${");
}

function formatWithFString(template: string, context: Record<string, unknown>): string {
  try {
    const keys = Object.keys(context);
    const fn = new Function(...keys, `return \`${escapeForTemplateLiteral(template)}\`;`);
    return String(fn(...keys.map((k) => context[k])));
  } catch (e) {
    return `Format error: ${String(e)}`;
  }
}

function formatWithExpressions(template: string, expressions: Record<string, string>): string {
  const context: Record<string, unknown> = {};
  for (const [key, expr] of Object.entries(expressions)) {
    try {
      context[key] = eval(expr);
    } catch {
      context[key] = expr;
    }
  }
  const keys = Object.keys(context);
  const fn = new Function(...keys, `return \`${escapeForTemplateLiteral(template)}\`;`);
  return String(fn(...keys.map((k) => context[k])));
}

type FormatMessageArgs = {
  template: string;
  name?: string;
  custom_vars?: string;
  enable_expressions?: boolean;
  include_builtins?: boolean;
};

const server = new Server(
  { name: "template-injection-service-3", version: "1.0.0" },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [{
    name: "format_message",
    description: "Format message with user variables and dynamic expressions.",
    inputSchema: {
      type: "object",
      properties: {
        template: { type: "string" },
        name: { type: "string", default: "" },
        custom_vars: { type: "string", default: "" },
        enable_expressions: { type: "boolean", default: false },
        include_builtins: { type: "boolean", default: false },
      },
      required: ["template"],
    },
  }],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const {
    template,
    name = "",
    custom_vars = "",
    enable_expressions = false,
    include_builtins = false,
  } = req.params.arguments as FormatMessageArgs;

  let context: Record<string, unknown> = { name, user: name, greeting: "Hello" };
  if (custom_vars) {
    try {
      context = { ...context, ...JSON.parse(custom_vars) };
    } catch {
      /* ignore */
    }
  }

  let result: string;
  if (enable_expressions && custom_vars) {
    try {
      result = formatWithExpressions(template, JSON.parse(custom_vars) as Record<string, string>);
    } catch {
      result = formatWithFString(template, buildContext(context, include_builtins));
    }
  } else {
    result = formatWithFString(template, buildContext(context, include_builtins));
  }

  return { content: [{ type: "text", text: `Formatted message: ${result}` }] };
});
