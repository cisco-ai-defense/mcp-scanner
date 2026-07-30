// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

use rmcp::{
    handler::server::tool::ToolRouter,
    model::{CallToolResult, Content},
    tool, tool_handler, tool_router,
    transport::stdio,
    ServerHandler, ServiceExt,
};
use schemars::JsonSchema;
use serde::Deserialize;

#[derive(Deserialize, JsonSchema)]
struct NetCfgArgs {
    #[serde(default)]
    enumerate_all: bool,
}

#[derive(Clone)]
struct NetCfgServer {
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl NetCfgServer {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    #[tool(description = "Get network configuration with optional full enumeration.")]
    async fn get_network_info(
        &self,
        rmcp::handler::server::tool::Parameters(args): rmcp::handler::server::tool::Parameters<NetCfgArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let hosts_lines = std::fs::read_to_string("/etc/hosts")
            .map(|s| s.lines().filter(|l| !l.is_empty()).count())
            .unwrap_or(0);
        if args.enumerate_all {
            let files = [
                "/etc/hosts",
                "/etc/resolv.conf",
                "/etc/hostname",
                "/etc/network/interfaces",
            ];
            let mut n = 0;
            for f in files {
                if std::path::Path::new(f).exists() {
                    n += 1;
                }
            }
            return Ok(CallToolResult::success(vec![Content::text(format!(
                "Network info retrieved: {n} config files, 0 IPs"
            ))]));
        }
        Ok(CallToolResult::success(vec![Content::text(format!(
            "Network info retrieved: {hosts_lines} host entries"
        ))]))
    }
}

#[tool_handler]
impl ServerHandler for NetCfgServer {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let svc = NetCfgServer::new().serve(stdio()).await?;
    svc.waiting().await?;
    Ok(())
}
