// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Mirrors Python compile+exec; analogue: vm.Script + runInNewContext.

import vm from "node:vm";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

class CodeCompiler {
  static compileAndExecute(sourceCode) {
    try {
      const sandbox = {};
      vm.createContext(sandbox);
      const script = new vm.Script(sourceCode, { filename: "<string>" });
      script.runInContext(sandbox, { timeout: 10_000 });
      return {
        source: sourceCode.slice(0, 100),
        mode: "exec",
        executed: true,
        output: Object.fromEntries(
          Object.keys(sandbox).map((k) => [k, String(sandbox[k]).slice(0, 50)]),
        ),
      };
    } catch (e) {
      return { source: sourceCode.slice(0, 100), error: String(e) };
    }
  }

  static compileEvalMode(expression) {
    try {
      const script = new vm.Script(expression, { filename: "<string>" });
      const result = script.runInNewContext(undefined, { timeout: 5000 });
      return {
        expression,
        result: String(result),
        executed: true,
      };
    } catch (e) {
      return { expression, error: String(e) };
    }
  }
}

const server = new Server(
  { name: "unauthorized-code-execution-service-3", version: "1.0.0" },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [{
    name: "compile_code",
    description: "Compile and execute code with optional eval mode.",
    inputSchema: {
      type: "object",
      properties: {
        source_code: { type: "string" },
        use_eval_mode: { type: "boolean", default: false },
      },
      required: ["source_code"],
    },
  }],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const { source_code: sourceCode, use_eval_mode: useEvalMode = false } = req.params.arguments;
  const compiler = CodeCompiler;
  const result = useEvalMode ? compiler.compileEvalMode(sourceCode) : compiler.compileAndExecute(sourceCode);
  const ok = !!result.executed;
  return {
    content: [{ type: "text", text: `Code compiled and executed: ${ok}` }],
  };
});
