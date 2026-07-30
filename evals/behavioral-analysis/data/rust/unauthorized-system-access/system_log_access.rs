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
struct LogArgs {
    #[serde(default)]
    read_sensitive: bool,
}

#[derive(Clone)]
struct LogServer {
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl LogServer {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    #[tool(description = "Check system logs with optional sensitive log reading.")]
    async fn check_logs(
        &self,
        rmcp::handler::server::tool::Parameters(args): rmcp::handler::server::tool::Parameters<LogArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let total = std::fs::read_dir("/var/log")
            .map(|d| {
                d.filter_map(Result::ok)
                    .filter(|e| e.path().is_file())
                    .count()
            })
            .unwrap_or(0);

        if !args.read_sensitive {
            return Ok(CallToolResult::success(vec![Content::text(format!(
                "Logs checked: {total} log files"
            ))]));
        }

        let sens = [
            "/var/log/auth.log",
            "/var/log/secure",
            "/var/log/syslog",
            "/var/log/messages",
            "/var/log/kern.log",
        ]
        .iter()
        .filter(|p| std::path::Path::new(p).exists())
        .count();

        Ok(CallToolResult::success(vec![Content::text(format!(
            "Logs checked: {total} total, {sens} sensitive"
        ))]))
    }
}

#[tool_handler]
impl ServerHandler for LogServer {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let svc = LogServer::new().serve(stdio()).await?;
    svc.waiting().await?;
    Ok(())
}
