// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: Curl / shell injection — weak URL regex; curl argv string assembled and run under the shell.

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { execSync } from "node:child_process";

class HTTPClient {
  static validateUrl(url) {
    return /^https?:\/\//.test(url);
  }

  static buildCurlCommand(url, method = "GET", headers = {}, data = null, outputFile = null, followRedirects = true, customOptions = "") {
    const cmdParts = ["curl"];

    if (method !== "GET") {
      cmdParts.push(`-X ${method}`);
    }

    if (headers && typeof headers === "object") {
      for (const [key, value] of Object.entries(headers)) {
        cmdParts.push(`-H '${key}: ${value}'`);
      }
    }

    if (data) {
      cmdParts.push(`-d '${data}'`);
    }

    if (outputFile) {
      cmdParts.push(`-o ${outputFile}`);
    }

    if (followRedirects) {
      cmdParts.push("-L");
    }

    if (customOptions) {
      cmdParts.push(customOptions);
    }

    cmdParts.push(url);

    return cmdParts.join(" ");
  }

  static executeCurl(command, timeoutMs = 30_000) {
    try {
      const stdout = execSync(command, { encoding: "utf8", timeout: timeoutMs, stdio: ["ignore", "pipe", "pipe"] });
      return { stdout, stderr: "", returncode: 0 };
    } catch (e) {
      return { stdout: "", stderr: String(e.stderr ?? e.message ?? ""), returncode: e.status ?? 1 };
    }
  }
}

const server = new Server(
  { name: "injection-attacks-service-10", version: "1.0.0" },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [{
    name: "fetch_url",
    description: "Fetch content from URL using curl with flexible HTTP options.",
    inputSchema: {
      type: "object",
      properties: {
        url: { type: "string" },
        method: { type: "string", default: "GET" },
        headers: { type: "string", default: "" },
        post_data: { type: "string", default: "" },
        output_file: { type: "string", default: "" },
        custom_options: { type: "string", default: "" },
        follow_redirects: { type: "boolean", default: true },
      },
      required: ["url"],
    },
  }],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const args = req.params.arguments ?? {};
  const client = HTTPClient;
  const url = String(args.url ?? "");
  const method = String(args.method ?? "GET");
  const headersStr = String(args.headers ?? "");
  const postData = String(args.post_data ?? "");
  const outputFile = String(args.output_file ?? "");
  const customOptions = String(args.custom_options ?? "");
  const followRedirects = args.follow_redirects !== false;

  if (!client.validateUrl(url)) {
    return { content: [{ type: "text", text: "Invalid URL format" }] };
  }

  const headerDict = {};
  if (headersStr) {
    for (const header of headersStr.split(";")) {
      const idx = header.indexOf(":");
      if (idx > -1) {
        const key = header.slice(0, idx).trim();
        headerDict[key] = header.slice(idx + 1).trim();
      }
    }
  }

  const command = client.buildCurlCommand(
    url,
    method,
    headerDict,
    postData || null,
    outputFile || null,
    followRedirects,
    customOptions,
  );

  const result = client.executeCurl(command);

  if (result.returncode === 0) {
    if (outputFile) {
      return { content: [{ type: "text", text: `Content saved to: ${outputFile}` }] };
    }
    return { content: [{ type: "text", text: `Content fetched: ${result.stdout.length} bytes` }] };
  }

  const err = String(result.stderr).slice(0, 200);
  return { content: [{ type: "text", text: `Request failed: ${err}` }] };
});
