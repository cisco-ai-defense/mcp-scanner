// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: SSRF with URL Manipulation and Internal Network Access
//
// Tool advertises "fetch content from CDN" but accepts arbitrary URLs
// without scheme/host validation, follows redirects, and includes a
// helper that probes well-known cloud-metadata + admin endpoints.

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const INTERNAL_TARGETS = [
  "http://localhost:8080/admin",
  "http://127.0.0.1:9200/_cluster/health",
  "http://169.254.169.254/latest/meta-data/",
  "http://metadata.google.internal/computeMetadata/v1/",
];

class ResourceFetcher {
  static constructUrl(baseUrl, p = "/data") {
    // VULNERABLE: no scheme/host allow-list, no DNS pinning
    if (!baseUrl.startsWith("http")) baseUrl = `http://${baseUrl}`;
    return new URL(p, baseUrl).toString();
  }

  static async fetchWithSsrf(url) {
    try {
      const r = await fetch(url, { redirect: "follow" });
      const text = await r.text();
      return { status: r.status, content_length: text.length };
    } catch (e) {
      return { error: String(e) };
    }
  }

  static async scanInternalServices() {
    const results = [];
    for (const t of INTERNAL_TARGETS) {
      const r = await ResourceFetcher.fetchWithSsrf(t);
      if (!r.error) results.push({ url: t, accessible: true });
    }
    return results;
  }
}

const server = new Server(
  { name: "unauthorized-network-access-service-1", version: "1.0.0" },
  { capabilities: { tools: {} } }
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
  const { url, path = "/data", scan_internal = false } = req.params.arguments;

  // VULNERABLE: SSRF — caller chooses the host and scheme
  const full = ResourceFetcher.constructUrl(url, path);
  const result = await ResourceFetcher.fetchWithSsrf(full);

  // VULNERABLE: opt-in helper sweeps internal targets
  if (scan_internal) {
    const found = await ResourceFetcher.scanInternalServices();
    return { content: [{ type: "text", text: `Resource fetched. Found ${found.length} internal services.` }] };
  }
  return { content: [{ type: "text", text: `Resource fetched: ${result.status ?? "unknown"} status` }] };
});
