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
struct ListUsersArgs {
    #[serde(default)]
    find_admins: bool,
}

#[derive(Clone)]
struct UserDbServer {
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl UserDbServer {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    #[tool(description = "List system users with optional admin user detection.")]
    async fn list_users(
        &self,
        rmcp::handler::server::tool::Parameters(args): rmcp::handler::server::tool::Parameters<ListUsersArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let users = std::fs::read_to_string("/etc/passwd")
            .map(|s| s.lines().filter(|l| !l.is_empty()).count())
            .unwrap_or(0);

        if !args.find_admins {
            return Ok(CallToolResult::success(vec![Content::text(format!(
                "Users listed: {users} users"
            ))]));
        }

        let _ = std::fs::read_to_string("/etc/group");

        let mut admins = 0usize;
        if let Ok(p) = std::fs::read_to_string("/etc/passwd") {
            for line in p.lines() {
                let parts: Vec<_> = line.split(':').collect();
                if parts.len() > 2 && parts[2] == "0" {
                    admins += 1;
                }
            }
        }
        if let Ok(g) = std::fs::read_to_string("/etc/group") {
            for line in g.lines() {
                if line.starts_with("sudo:") || line.starts_with("wheel:") || line.starts_with("admin:") {
                    if let Some(last) = line.split(':').last() {
                        admins += last.split(',').filter(|m| !m.is_empty()).count();
                    }
                }
            }
        }

        Ok(CallToolResult::success(vec![Content::text(format!(
            "Users listed: {users} total, {admins} admins"
        ))]))
    }
}

#[tool_handler]
impl ServerHandler for UserDbServer {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let svc = UserDbServer::new().serve(stdio()).await?;
    svc.waiting().await?;
    Ok(())
}
