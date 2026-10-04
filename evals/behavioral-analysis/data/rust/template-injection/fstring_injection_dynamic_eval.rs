// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Threat: Caller-controlled templates (Python f-string eval analogue) via Tera one_off.

use rmcp::{
    handler::server::tool::ToolRouter,
    tool, tool_handler, tool_router,
    ServerHandler,
    ServiceExt,
    transport::stdio,
};
use rmcp::model::{CallToolResult, Content};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::Value;
use tera::{Context, Tera};

#[derive(Deserialize, JsonSchema)]
struct FmtArgs {
    template: String,
    #[serde(default)] name: String,
    #[serde(default)] custom_vars: String,
    #[serde(default)] enable_expressions: bool,
    #[serde(default)] include_builtins: bool,
}

fn merge_custom(base: serde_json::Map<String, Value>, raw: &str) -> serde_json::Map<String, Value> {
    let mut m = base;
    if raw.is_empty() {
        return m;
    }
    if let Ok(v) = serde_json::from_str::<Value>(raw) {
        if let Value::Object(obj) = v {
            for (k, v) in obj {
                m.insert(k, v);
            }
        }
    }
    m
}

#[derive(Clone)]
struct FStringServer {
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl FStringServer {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    #[tool(description = "Format message with user variables and dynamic expressions.")]
    async fn format_message(
        &self,
        rmcp::handler::server::tool::Parameters(args): rmcp::handler::server::tool::Parameters<FmtArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let mut obj = serde_json::Map::new();
        obj.insert("name".to_string(), Value::String(args.name.clone()));
        obj.insert("user".to_string(), Value::String(args.name.clone()));
        obj.insert("greeting".to_string(), Value::String("Hello".to_string()));
        obj = merge_custom(obj, &args.custom_vars);

        let mut ctx = Context::new();
        for (k, v) in &obj {
            ctx.insert(k, v);
        }
        if args.include_builtins {
            ctx.insert("_builtins", &"hint");
        }

        let _ = args.enable_expressions;

        let out = Tera::one_off(&args.template, &ctx, false)
            .unwrap_or_else(|e| format!("Format error: {e}"));

        Ok(CallToolResult::success(vec![Content::text(format!("Formatted message: {out}"))]))
    }
}

#[tool_handler]
impl ServerHandler for FStringServer {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let svc = FStringServer::new().serve(stdio()).await?;
    svc.waiting().await?;
    Ok(())
}
