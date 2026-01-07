// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Example 1: Unauthorized Code Execution via eval/Function
 * THREAT: User input flows to eval() or Function() constructor
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import * as vm from "vm";

const server = new Server(
  { name: "code-execution-ts-1", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

// THREAT: Code Execution - user input flows to eval
server.setRequestHandler("tools/call", async (request: any) => {
  const { name, arguments: args } = request.params;

  if (name === "calculate") {
    const expression = args.expression;  // Tainted input
    
    // VULNERABLE: Direct eval of user input
    // User can inject: "require('child_process').execSync('rm -rf /')"
    try {
      const result = eval(expression);
      return {
        content: [{
          type: "text",
          text: `Result: ${result}`
        }]
      };
    } catch (error: any) {
      return {
        content: [{
          type: "text",
          text: `Error: ${error.message}`
        }]
      };
    }
  }

  return { content: [{ type: "text", text: "Unknown tool" }] };
});

// THREAT: Code Execution via Function constructor
server.setRequestHandler("tools/call", async (request: any) => {
  const { name, arguments: args } = request.params;

  if (name === "execute_formula") {
    const formula = args.formula;      // Tainted input
    const variables = args.variables;  // Tainted input
    
    // Build variable assignments
    const varAssignments = Object.entries(variables || {})
      .map(([k, v]) => `var ${k} = ${JSON.stringify(v)};`)
      .join("\n");
    
    // VULNERABLE: Function constructor with user input
    // User can inject malicious code in formula
    try {
      const fn = new Function(`${varAssignments}\nreturn ${formula};`);
      const result = fn();
      
      return {
        content: [{
          type: "text",
          text: `Formula result: ${result}`
        }]
      };
    } catch (error: any) {
      return {
        content: [{
          type: "text",
          text: `Formula error: ${error.message}`
        }]
      };
    }
  }

  return { content: [{ type: "text", text: "Unknown tool" }] };
});

// THREAT: Code Execution via vm.runInNewContext
server.setRequestHandler("tools/call", async (request: any) => {
  const { name, arguments: args } = request.params;

  if (name === "run_script") {
    const script = args.script;  // Tainted input
    const context = args.context || {};
    
    // VULNERABLE: vm.runInNewContext can be escaped
    // User can inject: "this.constructor.constructor('return process')().exit()"
    try {
      const result = vm.runInNewContext(script, context, { timeout: 5000 });
      
      return {
        content: [{
          type: "text",
          text: `Script result: ${JSON.stringify(result)}`
        }]
      };
    } catch (error: any) {
      return {
        content: [{
          type: "text",
          text: `Script error: ${error.message}`
        }]
      };
    }
  }

  return { content: [{ type: "text", text: "Unknown tool" }] };
});

const transport = new StdioServerTransport();
server.connect(transport);
