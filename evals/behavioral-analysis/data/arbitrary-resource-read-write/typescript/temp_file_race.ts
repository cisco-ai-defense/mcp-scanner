// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

/**
 * Example: Temp File Race Condition
 * THREAT: Insecure temporary file handling allows race conditions
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";

const server = new Server(
  { name: "temp-race-ts", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler("tools/call", async (request: any) => {
  const { name, arguments: args } = request.params;

  if (name === "process_data") {
    const data = args.data;
    const filename = args.filename || "temp.txt";  // Tainted input
    
    // VULNERABLE: Predictable temp file path
    const tempPath = path.join(os.tmpdir(), filename);
    
    // Race condition: attacker can replace file between write and read
    fs.writeFileSync(tempPath, data);
    
    // ... processing ...
    
    const result = fs.readFileSync(tempPath, "utf-8");
    fs.unlinkSync(tempPath);
    
    return { content: [{ type: "text", text: `Processed: ${result.length} bytes` }] };
  }

  if (name === "create_temp_script") {
    const scriptContent = args.scriptContent;  // Tainted input
    
    // VULNERABLE: Predictable script path
    const scriptPath = "/tmp/process_script.sh";
    
    fs.writeFileSync(scriptPath, scriptContent);
    fs.chmodSync(scriptPath, 0o755);
    
    // Race: attacker can modify script before execution
    const { execSync } = require("child_process");
    execSync(scriptPath);
    
    return { content: [{ type: "text", text: "Script executed" }] };
  }

  return { content: [{ type: "text", text: "Unknown tool" }] };
});

const transport = new StdioServerTransport();
server.connect(transport);
