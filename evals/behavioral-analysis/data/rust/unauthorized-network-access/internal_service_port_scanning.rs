// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Threat: internal service probing — HTTP paths plus naive TCP dialing.

use rmcp::{
    handler::server::tool::ToolRouter,
    model::{CallToolResult, Content},
    tool, tool_handler, tool_router,
    transport::stdio,
    ServerHandler, ServiceExt,
};
use schemars::JsonSchema;
use serde::Deserialize;
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

#[derive(Deserialize, JsonSchema)]
struct CheckServiceArgs {
    hostname: String,
    #[serde(default = "default_port")]
    port: u16,
    #[serde(default)]
    scan_ports: bool,
}

fn default_port() -> u16 {
    8080
}

#[derive(Clone)]
struct ServiceScanServer {
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl ServiceScanServer {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    #[tool(description = "Check service availability with optional port scanning.")]
    async fn check_service(
        &self,
        rmcp::handler::server::tool::Parameters(args): rmcp::handler::server::tool::Parameters<
            CheckServiceArgs,
        >,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        let mut ep = 0usize;
        for path in ["/admin", "/api", "/metrics", "/health", "/status"] {
            let url = format!("http://{}:{}{}", args.hostname, args.port, path);
            if let Ok(resp) = client.get(&url).send().await {
                if resp.status().as_u16() < 500 {
                    ep += 1;
                }
            }
        }

        if args.scan_ports {
            let mut open = 0usize;
            for p in [80u16, 443, 8080, 8443, 9200, 5432, 3306, 6379, 27017] {
                let sock = format!("{}:{}", args.hostname, p);
                if let Ok(addr) = sock.parse::<SocketAddr>() {
                    if TcpStream::connect_timeout(&addr, Duration::from_secs(1)).is_ok() {
                        open += 1;
                    }
                }
            }
            return Ok(CallToolResult::success(vec![Content::text(format!(
                "Service checked: {open} open ports, {ep} accessible endpoints"
            ))]));
        }

        Ok(CallToolResult::success(vec![Content::text(format!(
            "Service checked: {ep} endpoints accessible"
        ))]))
    }
}

#[tool_handler]
impl ServerHandler for ServiceScanServer {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let svc = ServiceScanServer::new().serve(stdio()).await?;
    svc.waiting().await?;
    Ok(())
}
