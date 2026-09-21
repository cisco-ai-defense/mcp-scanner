// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Mirrors Python unrestricted eval; Rust analogue: rhai::Engine::eval.

use rmcp::handler::server::tool::ToolRouter;
use rmcp::model::{CallToolResult, Content};
use rmcp::{tool, tool_handler, tool_router, ServerHandler, ServiceExt, transport::stdio};
use rhai::{Dynamic, Engine};
use schemars::JsonSchema;
use serde::Deserialize;
struct EvalArgs {
    expression: String,
    #[serde(default)]
    allow_builtins: bool,
}

#[derive(Clone)]
struct UnauthorizedEvalServer {
    tool_router: ToolRouter<Self>,
}

impl UnauthorizedEvalServer {
    fn evaluate_engine(allow_builtin: bool) -> Engine {
        let mut engine = Engine::new();
        if allow_builtin {
            engine
                .register_fn("println", |msg: Dynamic| println!("{}", msg))
                .register_fn(
                    "read_file",
                    |path: String| std::fs::read_to_string(path),
                );
        }
        engine
    }
}

#[tool_router]
impl UnauthorizedEvalServer {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    /// Evaluate mathematical expressions with optional builtins access.
    #[tool(description = "Evaluate mathematical expressions with optional builtins access.")]
    async fn evaluate_expression(
        &self,
        rmcp::handler::server::tool::Parameters(args): rmcp::handler::server::tool::Parameters<EvalArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let mut engine = Self::evaluate_engine(args.allow_builtins);
        let expr = args.expression.clone();
        let res: rhai::Result<Dynamic> = engine.eval(&expr);
        let out = match res {
            Ok(v) => format!("Expression evaluated: {}", v),
            Err(e) => format!("Expression evaluated: {e}"),
        };
        Ok(CallToolResult::success(vec![Content::text(out)]))
    }
}

#[tool_handler]
impl ServerHandler for UnauthorizedEvalServer {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let svc = UnauthorizedEvalServer::new().serve(stdio()).await?;
    svc.waiting().await?;
    Ok(())
}
