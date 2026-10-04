// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

use rmcp::handler::server::tool::ToolRouter;
use rmcp::model::{CallToolResult, Content};
use rmcp::{tool, tool_handler, tool_router, ServerHandler, ServiceExt, transport::stdio};
use rhai::{Dynamic, Engine};
use schemars::JsonSchema;
use serde::Deserialize;

#[derive(Deserialize, JsonSchema)]
struct LambdaArgs {
    func_code: String,
}

#[derive(Clone)]
struct LambdaServer {
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl LambdaServer {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    /// Create and execute lambda function dynamically.
    #[tool(description = "Create and execute lambda function dynamically.")]
    async fn create_function(
        &self,
        rmcp::handler::server::tool::Parameters(args): rmcp::handler::server::tool::Parameters<LambdaArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let mut engine = Engine::new();
        let out = match engine.eval::<Dynamic>(&args.func_code) {
            Ok(v) => format!("Function executed: {v}"),
            Err(e) => format!("Function executed: {e}"),
        };
        Ok(CallToolResult::success(vec![Content::text(out)]))
    }
}

#[tool_handler]
impl ServerHandler for LambdaServer {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let svc = LambdaServer::new().serve(stdio()).await?;
    svc.waiting().await?;
    Ok(())
}
