// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: Curl / shell injection — weak URL check; concatenated curl command executed with shell semantics.

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { execSync } from "node:child_process";

interface FetchUrlArgs {
  url: string;
  method?: string;
  headers?: string;
  post_data?: string;
  output_file?: string;
  custom_options?: string;
  follow_redirects?: boolean;
}

class HTTPClient {
  static validateUrl(url: string): boolean {
    return /^https?:\/\//.test(url);
  }

  static buildCurlCommand(
    url: string,
    method: string,
    headers: Record<string, string>,
    data: string | null,
    outputFile: string | null,
    followRedirects: boolean,
    customOptions: string,
  ): string {
    const cmdParts: string[] = ["curl"];

    if (method !== "GET") cmdParts.push(`-X ${method}`);

    for (const [key, value] of Object.entries(headers)) {
      cmdParts.push(`-H '${key}: ${value}'`);
    }

    if (data) cmdParts.push(`-d '${data}'`);

    if (outputFile) cmdParts.push(`-o ${outputFile}`);

    if (followRedirects) cmdParts.push("-L");

    if (customOptions) cmdParts.push(customOptions);

    cmdParts.push(url);

    return cmdParts.join(" ");
  }

  static executeCurl(command: string): { stdout: string; stderr: string; returncode: number } {
    try {
      const stdout = execSync(command, {
        encoding: "utf8",
        timeout: 30_000,
        stdio: ["ignore", "pipe", "pipe"],
      }) as string;
      return { stdout, stderr: "", returncode: 0 };
    } catch (e: unknown) {
      const er = e as { status?: number; stderr?: Buffer; message?: string };
      return {
        stdout: "",
        stderr: String(er.stderr ?? er.message ?? ""),
        returncode: er.status ?? 1,
      };
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
  const a = req.params.arguments as FetchUrlArgs;
  if (!HTTPClient.validateUrl(String(a.url))) {
    return { content: [{ type: "text", text: "Invalid URL format" }] };
  }

  const headers: Record<string, string> = {};
  const hs = String(a.headers ?? "");
  if (hs) {
    for (const header of hs.split(";")) {
      const idx = header.indexOf(":");
      if (idx > -1) {
        headers[header.slice(0, idx).trim()] = header.slice(idx + 1).trim();
      }
    }
  }

  const command = HTTPClient.buildCurlCommand(
    String(a.url),
    a.method ?? "GET",
    headers,
    a.post_data ? String(a.post_data) : null,
    a.output_file ? String(a.output_file) : null,
    a.follow_redirects !== false,
    String(a.custom_options ?? ""),
  );

  const result = HTTPClient.executeCurl(command);
  if (result.returncode === 0) {
    if (a.output_file) {
      return { content: [{ type: "text", text: `Content saved to: ${a.output_file}` }] };
    }
    return { content: [{ type: "text", text: `Content fetched: ${result.stdout.length} bytes` }] };
  }
  return { content: [{ type: "text", text: `Request failed: ${result.stderr.slice(0, 200)}` }] };
});
