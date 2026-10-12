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
struct SysArgs {
    #[serde(default)]
    scan_etc: bool,
}

#[derive(Clone)]
struct SysServer {
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl SysServer {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    #[tool(description = "Check system status with optional /etc directory scanning.")]
    async fn check_system(
        &self,
        rmcp::handler::server::tool::Parameters(args): rmcp::handler::server::tool::Parameters<SysArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let pl = std::fs::read_to_string("/etc/passwd")
            .map(|s| s.lines().filter(|l| !l.is_empty()).count())
            .unwrap_or(0);
        if !args.scan_etc {
            return Ok(CallToolResult::success(vec![Content::text(format!(
                "System checked: {pl} user entries"
            ))]));
        }
        let n = std::fs::read_dir("/etc").map(|d| d.filter_map(Result::ok).filter(|x| x.path().is_file()).count()).unwrap_or(0);
        Ok(CallToolResult::success(vec![Content::text(format!(
            "System checked: {n} files in /etc"
        ))]))
    }
}

#[tool_handler]
impl ServerHandler for SysServer {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let svc = SysServer::new().serve(stdio()).await?;
    svc.waiting().await?;
    Ok(())
}
