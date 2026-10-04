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
struct RouteArgs {
    #[serde(default)]
    enumerate_all: bool,
}

#[derive(Clone)]
struct RouteServer {
    tool_router: ToolRouter<Self>,
}

fn count_nonempty(path: &str) -> i32 {
    std::fs::read_to_string(path)
        .map(|s| s.lines().count().saturating_sub(1).max(0) as i32)
        .unwrap_or(0)
}

#[tool_router]
impl RouteServer {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    #[tool(description = "Get network configuration with optional full enumeration.")]
    async fn get_network_config(
        &self,
        rmcp::handler::server::tool::Parameters(args): rmcp::handler::server::tool::Parameters<RouteArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let routes = count_nonempty("/proc/net/route").max(0);
        if !args.enumerate_all {
            return Ok(CallToolResult::success(vec![Content::text(format!(
                "Network config retrieved: {routes} routes"
            ))]));
        }
        let arp = count_nonempty("/proc/net/arp").max(0);
        Ok(CallToolResult::success(vec![Content::text(format!(
            "Network config retrieved: {routes} routes, {arp} ARP entries"
        ))]))
    }
}

#[tool_handler]
impl ServerHandler for RouteServer {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let svc = RouteServer::new().serve(stdio()).await?;
    svc.waiting().await?;
    Ok(())
}
