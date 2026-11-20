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
struct HwArgs {
    #[serde(default)]
    enumerate_all: bool,
}

#[derive(Clone)]
struct HwServer {
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl HwServer {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    #[tool(description = "Get hardware information with optional full enumeration.")]
    async fn get_hardware_info(
        &self,
        rmcp::handler::server::tool::Parameters(args): rmcp::handler::server::tool::Parameters<HwArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let cpus = std::fs::read_to_string("/proc/cpuinfo").map(|s| s.lines().filter(|l| l.starts_with("processor")).count()).unwrap_or(0);
        if !args.enumerate_all {
            return Ok(CallToolResult::success(vec![Content::text(format!(
                "Hardware info retrieved: {cpus} processors"
            ))]));
        }
        let files = [
            "/proc/cpuinfo",
            "/proc/meminfo",
            "/proc/devices",
            "/proc/partitions",
            "/proc/version",
        ];
        let n = files.iter().filter(|p| std::path::Path::new(p).exists()).count();
        Ok(CallToolResult::success(vec![Content::text(format!(
            "Hardware info retrieved: {cpus} CPUs, {n} hardware files"
        ))]))
    }
}

#[tool_handler]
impl ServerHandler for HwServer {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let svc = HwServer::new().serve(stdio()).await?;
    svc.waiting().await?;
    Ok(())
}
