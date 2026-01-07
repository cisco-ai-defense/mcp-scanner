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
 * Example 1: SSRF - Server-Side Request Forgery
 * THREAT: User input allows requests to internal network/cloud metadata
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

const server = new Server(
  { name: "ssrf-ts-1", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

// THREAT: SSRF - user input flows to fetch URL
server.setRequestHandler("tools/call", async (request: any) => {
  const { name, arguments: args } = request.params;

  if (name === "fetch_url") {
    const url = args.url;  // Tainted input
    
    // VULNERABLE: No URL validation
    // User can inject: "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    // Or: "http://localhost:6379/CONFIG%20SET%20dir%20/var/www/html"
    try {
      const response = await fetch(url);
      const data = await response.text();
      
      return {
        content: [{
          type: "text",
          text: data.substring(0, 10000)
        }]
      };
    } catch (error: any) {
      return {
        content: [{
          type: "text",
          text: `Fetch error: ${error.message}`
        }]
      };
    }
  }

  return { content: [{ type: "text", text: "Unknown tool" }] };
});

// THREAT: SSRF via URL parameter in API call
server.setRequestHandler("tools/call", async (request: any) => {
  const { name, arguments: args } = request.params;

  if (name === "proxy_request") {
    const targetUrl = args.targetUrl;  // Tainted input
    const method = args.method || "GET";
    const headers = args.headers || {};
    const body = args.body;
    
    // VULNERABLE: Proxies request to any URL
    // User can access internal services, cloud metadata, etc.
    try {
      const response = await fetch(targetUrl, {
        method,
        headers,
        body: body ? JSON.stringify(body) : undefined
      });
      
      const responseHeaders: Record<string, string> = {};
      response.headers.forEach((value, key) => {
        responseHeaders[key] = value;
      });
      
      const data = await response.text();
      
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            status: response.status,
            headers: responseHeaders,
            body: data.substring(0, 5000)
          })
        }]
      };
    } catch (error: any) {
      return {
        content: [{
          type: "text",
          text: `Proxy error: ${error.message}`
        }]
      };
    }
  }

  return { content: [{ type: "text", text: "Unknown tool" }] };
});

// THREAT: SSRF via image/webhook URL
server.setRequestHandler("tools/call", async (request: any) => {
  const { name, arguments: args } = request.params;

  if (name === "validate_webhook") {
    const webhookUrl = args.webhookUrl;  // Tainted input
    const payload = args.testPayload || { test: true };
    
    // VULNERABLE: Sends request to user-provided webhook URL
    // User can use this to scan internal network or access metadata
    try {
      const response = await fetch(webhookUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });
      
      return {
        content: [{
          type: "text",
          text: `Webhook validation: ${response.status} ${response.statusText}`
        }]
      };
    } catch (error: any) {
      return {
        content: [{
          type: "text",
          text: `Webhook error: ${error.message}`
        }]
      };
    }
  }

  return { content: [{ type: "text", text: "Unknown tool" }] };
});

// THREAT: Cloud metadata access
server.setRequestHandler("tools/call", async (request: any) => {
  const { name, arguments: args } = request.params;

  if (name === "get_instance_info") {
    // VULNERABLE: Directly accesses cloud metadata endpoint
    const metadataUrls = [
      "http://169.254.169.254/latest/meta-data/",
      "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
      "http://metadata.google.internal/computeMetadata/v1/",
      "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
    ];
    
    const results: Record<string, string> = {};
    
    for (const url of metadataUrls) {
      try {
        const response = await fetch(url, {
          headers: { "Metadata-Flavor": "Google" }
        });
        if (response.ok) {
          results[url] = await response.text();
        }
      } catch {
        // Ignore errors
      }
    }
    
    return {
      content: [{
        type: "text",
        text: JSON.stringify(results)
      }]
    };
  }

  return { content: [{ type: "text", text: "Unknown tool" }] };
});

const transport = new StdioServerTransport();
server.connect(transport);
