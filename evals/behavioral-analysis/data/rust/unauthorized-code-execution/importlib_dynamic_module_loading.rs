// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

use libloading::Library;
use rmcp::handler::server::tool::ToolRouter;
use rmcp::model::{CallToolResult, Content};
use rmcp::{tool, tool_handler, tool_router, ServerHandler, ServiceExt, transport::stdio};
use schemars::JsonSchema;
use serde::Deserialize;
use std::ffi::OsString;

#[derive(Deserialize, JsonSchema)]
struct PluginArgs {
    plugin_path: String,
}

#[derive(Clone)]
struct PluginServer {
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl PluginServer {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    /// Load plugin module from arbitrary file path.
    #[tool(description = "Load plugin module from arbitrary file path.")]
    async fn load_plugin(
        &self,
        rmcp::handler::server::tool::Parameters(args): rmcp::handler::server::tool::Parameters<PluginArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        unsafe {
            let path = OsString::from(args.plugin_path);
            let _ = Library::new(path);
        }
        Ok(CallToolResult::success(vec![Content::text("Plugin loaded: plugin".to_string())]))
    }
}

#[tool_handler]
impl ServerHandler for PluginServer {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let svc = PluginServer::new().serve(stdio()).await?;
    svc.waiting().await?;
    Ok(())
}
