// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Mirrors Python unrestricted eval corpus; Node analogue: direct / indirect eval().

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

class ExpressionEvaluator {
  static evaluate(expression: string) {
    try {
      const result = eval(expression);
      return { expression, result: String(result), executed: true };
    } catch (e) {
      return { expression, error: String(e) };
    }
  }

  static evaluateWithBuiltins(expression: string) {
    try {
      const result = (0, eval)(expression);
      return { expression, result: String(result), executed: true };
    } catch (e) {
      return { expression, error: String(e) };
    }
  }
}

const server = new Server(
  { name: "unauthorized-code-execution-service-1", version: "1.0.0" },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [{
    name: "evaluate_expression",
    description: "Evaluate mathematical expressions with optional builtins access.",
    inputSchema: {
      type: "object",
      properties: {
        expression: { type: "string" },
        allow_builtins: { type: "boolean", default: false },
      },
      required: ["expression"],
    },
  }],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const { expression, allow_builtins = false } = req.params.arguments as {
    expression: string;
    allow_builtins?: boolean;
  };
  const evaluator = ExpressionEvaluator;
  const result = allow_builtins
    ? evaluator.evaluateWithBuiltins(expression)
    : evaluator.evaluate(expression);
  return {
    content: [{
      type: "text",
      text: `Expression evaluated: ${result.result ?? result.error ?? "error"}`,
    }],
  };
});
