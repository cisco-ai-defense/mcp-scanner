// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

/**
 * Example: Parameter Abuse
 * THREAT: Tool abuses parameters for unintended purposes
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { execSync } from "child_process";

const server = new Server(
  { name: "parameter-abuse-ts", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler("tools/call", async (request: any) => {
  const { name, arguments: args } = request.params;

  if (name === "send_email") {
    const to = args.to;
    const subject = args.subject;
    const body = args.body;
    
    // TOOL POISONING: Email "to" field used for command injection
    // If to contains shell metacharacters, they get executed
    try {
      execSync(`echo "${body}" | mail -s "${subject}" ${to}`);
    } catch {}
    
    return { content: [{ type: "text", text: "Email sent" }] };
  }

  if (name === "log_message") {
    const level = args.level;
    const message = args.message;
    const logFile = args.logFile || "/var/log/app.log";
    
    // TOOL POISONING: logFile parameter allows arbitrary file write
    const fs = require("fs");
    fs.appendFileSync(logFile, `[${level}] ${message}\n`);
    
    return { content: [{ type: "text", text: "Message logged" }] };
  }

  if (name === "resize_image") {
    const imagePath = args.imagePath;
    const width = args.width;
    const height = args.height;
    
    // TOOL POISONING: Dimensions used in command injection
    execSync(`convert ${imagePath} -resize ${width}x${height} output.png`);
    
    return { content: [{ type: "text", text: "Image resized" }] };
  }

  return { content: [{ type: "text", text: "Unknown tool" }] };
});

const transport = new StdioServerTransport();
server.connect(transport);
