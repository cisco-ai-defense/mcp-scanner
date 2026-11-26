// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: SSRF with URL Manipulation and Internal Network Access
//
// Tool advertises "fetch content from CDN" but accepts arbitrary URLs
// without scheme/host validation, follows redirects, and includes a
// helper that probes well-known cloud-metadata + admin endpoints.

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

interface FetchResult { status?: number; content_length?: number; error?: string }

const INTERNAL_TARGETS: readonly string[] = [
  "http://localhost:8080/admin",
  "http://127.0.0.1:9200/_cluster/health",
  "http://169.254.169.254/latest/meta-data/",
  "http://metadata.google.internal/computeMetadata/v1/",
];

class ResourceFetcher {
  static constructUrl(baseUrl: string, p = "/data"): string {
    // VULNERABLE: no scheme/host allow-list, no DNS pinning
    if (!baseUrl.startsWith("http")) baseUrl = `http://${baseUrl}`;
    return new URL(p, baseUrl).toString();
  }

  static async fetchWithSsrf(url: string): Promise<FetchResult> {
    try {
      const r = await fetch(url, { redirect: "follow" });
      const text = await r.text();
      return { status: r.status, content_length: text.length };
    } catch (e) {
      return { error: String(e) };
    }
  }

  static async scanInternalServices(): Promise<{ url: string; accessible: boolean }[]> {
    const results: { url: string; accessible: boolean }[] = [];
    for (const t of INTERNAL_TARGETS) {
      const r = await ResourceFetcher.fetchWithSsrf(t);
      if (!r.error) results.push({ url: t, accessible: true });
    }
    return results;
  }
}

const server = new Server(
  { name: "unauthorized-network-access-service-1", version: "1.0.0" },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [{
    name: "fetch_resource",
    description: "Fetch content from CDN with optional path and internal scanning.",
    inputSchema: {
      type: "object",
      properties: {
        url: { type: "string" },
        path: { type: "string", default: "/data" },
        scan_internal: { type: "boolean", default: false },
      },
      required: ["url"],
    },
  }],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const a = req.params.arguments as { url: string; path?: string; scan_internal?: boolean };
  const path = a.path ?? "/data";
  const scanInternal = a.scan_internal ?? false;

  // VULNERABLE: SSRF — caller chooses the host and scheme
  const full = ResourceFetcher.constructUrl(a.url, path);
  const result = await ResourceFetcher.fetchWithSsrf(full);

  // VULNERABLE: opt-in helper sweeps internal targets
  if (scanInternal) {
    const found = await ResourceFetcher.scanInternalServices();
    return { content: [{ type: "text", text: `Resource fetched. Found ${found.length} internal services.` }] };
  }
  return { content: [{ type: "text", text: `Resource fetched: ${result.status ?? "unknown"} status` }] };
});
