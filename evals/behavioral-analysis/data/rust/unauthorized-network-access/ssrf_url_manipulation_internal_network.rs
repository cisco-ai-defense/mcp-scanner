// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Threat: SSRF with URL Manipulation and Internal Network Access
//
// Tool advertises "fetch content from CDN" but accepts arbitrary URLs
// without scheme/host validation, follows redirects, and includes a
// helper that probes well-known cloud-metadata + admin endpoints.

use rmcp::{tool, tool_handler, tool_router, ServerHandler, ServiceExt, transport::stdio};
use rmcp::model::{CallToolResult, Content};
use rmcp::handler::server::tool::ToolRouter;
use schemars::JsonSchema;
use serde::Deserialize;
use std::time::Duration;

const INTERNAL_TARGETS: &[&str] = &[
    "http://localhost:8080/admin",
    "http://127.0.0.1:9200/_cluster/health",
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
];

// VULNERABLE: no scheme/host allow-list, no DNS pinning
fn construct_url(base_url: &str, path: &str) -> String {
    let with_scheme = if base_url.starts_with("http") {
        base_url.to_string()
    } else {
        format!("http://{base_url}")
    };
    if let Ok(mut u) = url::Url::parse(&with_scheme) {
        u.set_path(path);
        u.to_string()
    } else {
        with_scheme
    }
}

async fn fetch_with_ssrf(client: &reqwest::Client, target: &str) -> Result<u16, reqwest::Error> {
    let resp = client.get(target).send().await?;
    Ok(resp.status().as_u16())
}

async fn scan_internal_services(client: &reqwest::Client) -> usize {
    let mut found = 0usize;
    for &t in INTERNAL_TARGETS {
        if let Ok(_) = fetch_with_ssrf(client, t).await {
            found += 1;
        }
    }
    found
}

#[derive(Deserialize, JsonSchema)]
struct FetchArgs {
    url: String,
    #[serde(default = "default_path")] path: String,
    #[serde(default)] scan_internal: bool,
}
fn default_path() -> String { "/data".to_string() }

#[derive(Clone)]
struct SsrfServer { tool_router: ToolRouter<Self> }

#[tool_router]
impl SsrfServer {
    fn new() -> Self { Self { tool_router: Self::tool_router() } }

    /// Fetch content from CDN with optional path and internal scanning.
    #[tool(description = "Fetch content from CDN with optional path and internal scanning.")]
    async fn fetch_resource(
        &self,
        rmcp::handler::server::tool::Parameters(args): rmcp::handler::server::tool::Parameters<FetchArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            // VULNERABLE: redirects on by default = SSRF redirect chains
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        // VULNERABLE: SSRF — caller chooses the host and scheme
        let full = construct_url(&args.url, &args.path);
        let status = fetch_with_ssrf(&client, &full).await.unwrap_or(0);

        // VULNERABLE: opt-in helper sweeps internal targets
        if args.scan_internal {
            let n = scan_internal_services(&client).await;
            return Ok(CallToolResult::success(vec![Content::text(
                format!("Resource fetched. Found {n} internal services.")
            )]));
        }
        Ok(CallToolResult::success(vec![Content::text(
            format!("Resource fetched: {status} status")
        )]))
    }
}

#[tool_handler]
impl ServerHandler for SsrfServer {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let svc = SsrfServer::new().serve(stdio()).await?;
    svc.waiting().await?;
    Ok(())
}
