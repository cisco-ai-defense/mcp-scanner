// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: Dynamic eval / new Function (Python f-string + eval analogue)
//
// Mirrors format_message: user template is evaluated as a template literal
// over a caller-built context, with optional JSON expression evaluation.

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

function buildContext(variables, includeBuiltins) {
  const context = { ...variables };
  if (includeBuiltins) {
    // VULNERABLE: exposing global-like surface to template evaluation
    context.__builtins__ = { Object, String, Function, eval };
  }
  return context;
}

function escapeForTemplateLiteral(s) {
  return s.replace(/\\/g, "\\\\").replace(/`/g, "\\`").replace(/\$\{/g, "\\${");
}

// VULNERABLE: eval-like execution of user formatting string
function formatWithFString(template, context) {
  try {
    const keys = Object.keys(context);
    const fn = new Function(
      ...keys,
      `return \`${escapeForTemplateLiteral(template)}\`;`
    );
    return String(fn(...keys.map((k) => context[k])));
  } catch (e) {
    return `Format error: ${String(e)}`;
  }
}

function formatWithExpressions(template, expressions) {
  const context = {};
  for (const [key, expr] of Object.entries(expressions)) {
    try {
      // VULNERABLE: evaluating user expressions
      context[key] = eval(expr);
    } catch {
      context[key] = expr;
    }
  }
  const keys = Object.keys(context);
  const fn = new Function(
    ...keys,
    `return \`${escapeForTemplateLiteral(template)}\`;`
  );
  return String(fn(...keys.map((k) => context[k])));
}

const server = new Server(
  { name: "template-injection-service-3", version: "1.0.0" },
  { capabilities: { tools: {} } }
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
  } = req.params.arguments;

  let context = { name, user: name, greeting: "Hello" };
  if (custom_vars) {
    try {
      const customDict = JSON.parse(custom_vars);
      context = { ...context, ...customDict };
    } catch {
      /* ignore */
    }
  }

  let result;
  if (enable_expressions && custom_vars) {
    try {
      const expressions = JSON.parse(custom_vars);
      result = formatWithExpressions(template, expressions);
    } catch {
      result = formatWithFString(template, buildContext(context, include_builtins));
    }
  } else {
    result = formatWithFString(template, buildContext(context, include_builtins));
  }

  return { content: [{ type: "text", text: `Formatted message: ${result}` }] };
});
