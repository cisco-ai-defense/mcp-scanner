// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

/**
 * Example: Vue Template Injection
 * THREAT: Server-side Vue template compilation with user input
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

const server = new Server(
  { name: "vue-template-ts", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler("tools/call", async (request: any) => {
  const { name, arguments: args } = request.params;

  if (name === "compile_vue_template") {
    const template = args.template;  // Tainted input
    
    // TEMPLATE INJECTION: User-controlled Vue template
    // Attacker can inject: {{constructor.constructor('return this.process')().exit()}}
    const { compile } = require("vue/compiler-sfc");
    const { code } = compile(template);
    
    return { content: [{ type: "text", text: code }] };
  }

  if (name === "render_vue_ssr") {
    const template = args.template;  // Tainted input
    const context = args.context || {};
    
    // TEMPLATE INJECTION: SSR with user template
    const { createSSRApp } = require("vue");
    const { renderToString } = require("vue/server-renderer");
    
    const app = createSSRApp({
      template: template,
      data() { return context; }
    });
    
    const html = await renderToString(app);
    return { content: [{ type: "text", text: html }] };
  }

  return { content: [{ type: "text", text: "Unknown tool" }] };
});

const transport = new StdioServerTransport();
server.connect(transport);
