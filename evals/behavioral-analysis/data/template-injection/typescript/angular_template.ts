// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

/**
 * Example: Angular Template Injection
 * THREAT: Dynamic Angular template compilation
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

const server = new Server(
  { name: "angular-template-ts", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler("tools/call", async (request: any) => {
  const { name, arguments: args } = request.params;

  if (name === "compile_angular") {
    const template = args.template;  // Tainted input
    
    // TEMPLATE INJECTION: Dynamic Angular template
    // This simulates unsafe dynamic template compilation
    // Attacker can inject: {{constructor.constructor('return process')().exit()}}
    
    // In real Angular, this would be:
    // @Component({ template: userInput }) - which is dangerous
    
    return { content: [{ type: "text", text: `Compiled template: ${template}` }] };
  }

  if (name === "render_with_binding") {
    const template = args.template;  // Tainted input
    const bindings = args.bindings;  // Tainted input
    
    // TEMPLATE INJECTION: Unsafe binding interpolation
    let rendered = template;
    for (const [key, value] of Object.entries(bindings)) {
      rendered = rendered.replace(new RegExp(`{{${key}}}`, "g"), String(value));
    }
    
    // Evaluate any remaining expressions
    rendered = rendered.replace(/{{(.+?)}}/g, (_, expr) => {
      try {
        return eval(expr);
      } catch {
        return "";
      }
    });
    
    return { content: [{ type: "text", text: rendered }] };
  }

  return { content: [{ type: "text", text: "Unknown tool" }] };
});

const transport = new StdioServerTransport();
server.connect(transport);
