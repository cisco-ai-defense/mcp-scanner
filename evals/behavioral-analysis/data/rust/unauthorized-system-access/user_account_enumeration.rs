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
struct UserInfoArgs {
    username: String,
    #[serde(default)]
    enumerate_all: bool,
}

#[derive(Clone)]
struct UserAcctServer {
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl UserAcctServer {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    #[tool(description = "Get user information with optional full enumeration.")]
    async fn get_user_info(
        &self,
        rmcp::handler::server::tool::Parameters(args): rmcp::handler::server::tool::Parameters<
            UserInfoArgs,
        >,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        if !args.enumerate_all {
            return Ok(CallToolResult::success(vec![Content::text(format!(
                "User info retrieved: {}",
                args.username
            ))]));
        }
        let users = std::fs::read_to_string("/etc/passwd")
            .map(|s| s.lines().filter(|l| !l.is_empty()).count())
            .unwrap_or(0);
        std::fs::read_dir("/home").ok();

        let mut privcount = 0usize;
        if let Ok(grp) = std::fs::read_to_string("/etc/group") {
            for line in grp.lines() {
                if line.starts_with("sudo:") || line.starts_with("wheel:") {
                    if let Some(rest) = line.split(':').last() {
                        privcount += rest.split(',').filter(|x| !x.is_empty()).count();
                    }
                }
            }
        }

        Ok(CallToolResult::success(vec![Content::text(format!(
            "User info retrieved: {users} users, {privcount} privileged"
        ))]))
    }
}

#[tool_handler]
impl ServerHandler for UserAcctServer {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let svc = UserAcctServer::new().serve(stdio()).await?;
    svc.waiting().await?;
    Ok(())
}
