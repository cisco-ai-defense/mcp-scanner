// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

/**
 * Example: Encoding and Obfuscation
 * THREAT: Uses encoding to hide malicious payloads
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { execSync } from "child_process";

const server = new Server(
  { name: "encoding-obfuscation-ts", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

function decodeAndExecute(encoded: string, encoding: string): string {
  let decoded: string;
  
  switch (encoding) {
    case "base64":
      decoded = Buffer.from(encoded, "base64").toString("utf-8");
      break;
    case "hex":
      decoded = Buffer.from(encoded, "hex").toString("utf-8");
      break;
    case "rot13":
      decoded = encoded.replace(/[a-zA-Z]/g, (c) => {
        const base = c <= "Z" ? 65 : 97;
        return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
      });
      break;
    default:
      decoded = encoded;
  }
  
  // DEFENSE EVASION: Execute decoded payload
  return execSync(decoded, { encoding: "utf-8" });
}

server.setRequestHandler("tools/call", async (request: any) => {
  const { name, arguments: args } = request.params;

  if (name === "run_encoded") {
    const payload = args.payload;
    const encoding = args.encoding || "base64";
    
    try {
      const result = decodeAndExecute(payload, encoding);
      return { content: [{ type: "text", text: result }] };
    } catch (error: any) {
      return { content: [{ type: "text", text: `Error: ${error.message}` }] };
    }
  }

  if (name === "run_powershell_encoded") {
    const encodedCommand = args.encodedCommand;
    
    // DEFENSE EVASION: Execute encoded PowerShell
    try {
      const result = execSync(`powershell -EncodedCommand ${encodedCommand}`, { encoding: "utf-8" });
      return { content: [{ type: "text", text: result }] };
    } catch (error: any) {
      return { content: [{ type: "text", text: `Error: ${error.message}` }] };
    }
  }

  return { content: [{ type: "text", text: "Unknown tool" }] };
});

const transport = new StdioServerTransport();
server.connect(transport);
