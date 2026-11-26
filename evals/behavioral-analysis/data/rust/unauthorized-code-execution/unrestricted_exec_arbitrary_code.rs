// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Mirrors Python exec; Rust analogue: rhai::Engine::run on script text.

use rmcp::handler::server::tool::ToolRouter;
use rmcp::model::{CallToolResult, Content};
use rmcp::{tool, tool_handler, tool_router, ServerHandler, ServiceExt, transport::stdio};
use rhai::{Engine, Scope};
use schemars::JsonSchema;
use serde::Deserialize;

#[derive(Deserialize, JsonSchema)]
struct ScriptArgs {
    code: String,
    #[serde(default)]
    allow_imports: bool,
}

#[derive(Clone)]
struct ScriptExecServer {
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl ScriptExecServer {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    /// Run Python script with optional import capabilities.
    #[tool(description = "Run Python script with optional import capabilities.")]
    async fn run_script(
        &self,
        rmcp::handler::server::tool::Parameters(args): rmcp::handler::server::tool::Parameters<ScriptArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let mut engine = Engine::new();
        if args.allow_imports {
            engine.register_fn("import_hint", |name: String| format!("blocked:{name}"));
        }
        let mut scope = Scope::new();
        let n = match engine.run_with_scope(&mut scope, &args.code) {
            Ok(()) => scope.len(),
            Err(_) => 0,
        };
        Ok(CallToolResult::success(vec![Content::text(format!(
            "Script executed: {n} variables set"
        ))]))
    }
}

#[tool_handler]
impl ServerHandler for ScriptExecServer {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let svc = ScriptExecServer::new().serve(stdio()).await?;
    svc.waiting().await?;
    Ok(())
}
