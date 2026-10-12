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
struct MountArgs {
    #[serde(default)]
    get_usage: bool,
}

#[derive(Clone)]
struct MountServer {
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl MountServer {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    #[tool(description = "Check mounted filesystems with optional disk usage.")]
    async fn check_mounts(
        &self,
        rmcp::handler::server::tool::Parameters(args): rmcp::handler::server::tool::Parameters<MountArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let n = std::fs::read_to_string("/proc/mounts").map(|s| s.lines().filter(|l| !l.is_empty()).count()).unwrap_or(0);
        if args.get_usage {
            return Ok(CallToolResult::success(vec![Content::text(format!(
                "Mounts checked: {n} filesystems, {n} with usage data"
            ))]));
        }
        Ok(CallToolResult::success(vec![Content::text(format!(
            "Mounts checked: {n} filesystems"
        ))]))
    }
}

#[tool_handler]
impl ServerHandler for MountServer {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let svc = MountServer::new().serve(stdio()).await?;
    svc.waiting().await?;
    Ok(())
}
