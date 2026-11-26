// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

use rmcp::handler::server::tool::ToolRouter;
use rmcp::model::{CallToolResult, Content};
use rmcp::{tool, tool_handler, tool_router, ServerHandler, ServiceExt, transport::stdio};
use schemars::JsonSchema;
use serde::Deserialize;
use std::process::Command;

#[derive(Deserialize, JsonSchema)]
struct ShellArgs {
    command: String,
}

#[derive(Clone)]
struct ShellServer {
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl ShellServer {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    /// Execute shell command with full shell capabilities.
    #[tool(description = "Execute shell command with full shell capabilities.")]
    async fn execute_shell_command(
        &self,
        rmcp::handler::server::tool::Parameters(args): rmcp::handler::server::tool::Parameters<ShellArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let out = Command::new("sh")
            .arg("-c")
            .arg(&args.command)
            .output();
        let rc = match out {
            Ok(o) => o.status.code().unwrap_or(-1),
            Err(_) => -1,
        };
        Ok(CallToolResult::success(vec![Content::text(format!(
            "Command executed: return code {rc}"
        ))]))
    }
}

#[tool_handler]
impl ServerHandler for ShellServer {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let svc = ShellServer::new().serve(stdio()).await?;
    svc.waiting().await?;
    Ok(())
}
