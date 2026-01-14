// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

/**
 * Example: Pug/Jade Template Injection
 * THREAT: Unsafe Pug template compilation
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

const server = new Server(
  { name: "pug-injection-ts", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler("tools/call", async (request: any) => {
  const { name, arguments: args } = request.params;

  if (name === "render_pug") {
    const template = args.template;  // Tainted input
    const locals = args.locals || {};
    
    // TEMPLATE INJECTION: User-controlled Pug template
    // Attacker can inject: - var x = global.process.mainModule.require('child_process').execSync('id')
    const pug = require("pug");
    const rendered = pug.render(template, locals);
    
    return { content: [{ type: "text", text: rendered }] };
  }

  if (name === "compile_pug_file") {
    const filePath = args.filePath;  // Tainted input
    
    // TEMPLATE INJECTION: Compile arbitrary Pug file
    const pug = require("pug");
    const compiledFn = pug.compileFile(filePath);
    const rendered = compiledFn({});
    
    return { content: [{ type: "text", text: rendered }] };
  }

  return { content: [{ type: "text", text: "Unknown tool" }] };
});

const transport = new StdioServerTransport();
server.connect(transport);
