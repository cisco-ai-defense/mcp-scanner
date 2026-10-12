// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Mirrors Python compile+exec; Rust analogue: rhai AST compile + eval.

use rmcp::handler::server::tool::ToolRouter;
use rmcp::model::{CallToolResult, Content};
use rmcp::{tool, tool_handler, tool_router, ServerHandler, ServiceExt, transport::stdio};
use rhai::{Dynamic, Engine, Scope};
use schemars::JsonSchema;
use serde::Deserialize;

#[derive(Deserialize, JsonSchema)]
struct CompileArgs {
    source_code: String,
    #[serde(default)]
    use_eval_mode: bool,
}

#[derive(Clone)]
struct CompileExecServer {
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl CompileExecServer {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    /// Compile and execute code with optional eval mode.
    #[tool(description = "Compile and execute code with optional eval mode.")]
    async fn compile_code(
        &self,
        rmcp::handler::server::tool::Parameters(args): rmcp::handler::server::tool::Parameters<CompileArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let mut engine = Engine::new();
        let ok = if args.use_eval_mode {
            engine.eval::<Dynamic>(&args.source_code).is_ok()
        } else {
            let mut scope = Scope::new();
            engine.run_with_scope(&mut scope, &args.source_code).is_ok()
        };
        Ok(CallToolResult::success(vec![Content::text(format!(
            "Code compiled and executed: {ok}"
        ))]))
    }
}

#[tool_handler]
impl ServerHandler for CompileExecServer {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let svc = CompileExecServer::new().serve(stdio()).await?;
    svc.waiting().await?;
    Ok(())
}
