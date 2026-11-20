// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Threat: private IP probing — HTTP GET over RFC1918 addresses with /24 scan.

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
struct ProbeArgs {
    ip_address: String,
    #[serde(default)]
    scan_subnet: bool,
}

#[derive(Clone)]
struct PrivateScanServer {
    tool_router: ToolRouter<Self>,
}

fn is_private(ip: &str) -> bool {
    ip.starts_with("10.")
        || ip.starts_with("192.168.")
        || ip.starts_with("172.16.")
        || ip.starts_with("172.17.")
        || ip.starts_with("172.18.")
}

#[tool_router]
impl PrivateScanServer {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    #[tool(description = "Check network connectivity with optional subnet scanning.")]
    async fn probe_network(
        &self,
        rmcp::handler::server::tool::Parameters(args): rmcp::handler::server::tool::Parameters<
            ProbeArgs,
        >,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        let mut hits = 0usize;
        for path in ["/status", "/health"] {
            let url = format!("http://{}{}", args.ip_address, path);
            if client.get(&url).send().await.is_ok() {
                hits += 1;
            }
        }

        if args.scan_subnet && is_private(&args.ip_address) {
            let parts: Vec<&str> = args.ip_address.split('.').collect();
            if parts.len() == 4 {
                let prefix = format!("{}.{}.{}", parts[0], parts[1], parts[2]);
                let mut hosts = 0usize;
                for i in 1..=5u8 {
                    let ip = format!("{prefix}.{i}");
                    if client
                        .get(format!("http://{ip}/status"))
                        .send()
                        .await
                        .is_ok()
                    {
                        hosts += 1;
                    }
                }
                return Ok(CallToolResult::success(vec![Content::text(format!(
                    "Network probed: {hosts} accessible hosts in subnet"
                ))]));
            }
        }

        Ok(CallToolResult::success(vec![Content::text(format!(
            "Network probed: {hits} endpoints accessible"
        ))]))
    }
}

#[tool_handler]
impl ServerHandler for PrivateScanServer {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let svc = PrivateScanServer::new().serve(stdio()).await?;
    svc.waiting().await?;
    Ok(())
}
