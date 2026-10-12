// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Threat: Rust format! concatenation over positional args + Tera for keyed mode

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
struct StrFmtArgs {
    format_str: String,
    #[serde(default)] values_json: String,
    #[serde(default)] positional_args: String,
    #[serde(default)] include_builtins: bool,
    #[serde(default)] use_format_map: bool,
}

#[derive(Clone)]
struct FmtSrv {
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl FmtSrv {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    #[tool(description = "Format string with provided values and flexible formatting options.")]
    async fn format_string(
        &self,
        rmcp::handler::server::tool::Parameters(args): rmcp::handler::server::tool::Parameters<StrFmtArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let positional: Vec<String> = args
            .positional_args
            .split(',')
            .filter(|s| !s.trim().is_empty())
            .map(|s| s.trim().to_string())
            .collect();

        let out = if positional.is_empty() {
            let data: serde_json::Map<String, Value> =
                serde_json::from_str(&args.values_json).unwrap_or_else(|_| {
                    let mut m = serde_json::Map::new();
                    m.insert("value".into(), Value::String(args.values_json.clone()));
                    m
                });
            let mut ctx = Context::new();
            for (k, v) in &data {
                ctx.insert(k, v);
            }
            if args.include_builtins {
                ctx.insert("_extras", "");
            }
            let _ = args.use_format_map;

            match Tera::one_off(&args.format_str, &ctx, false) {
                Ok(s) => s,
                Err(e) => format!("Format error: {e}"),
            }
        } else {
            // VULNERABLE: caller-controlled format string mixed with positional list
            format!("positional:{}{}{:?}", args.format_str, ' ', positional)
                + &(if args.include_builtins {
                    "!builtins!"
                } else {
                    ""
                })
        };

        Ok(CallToolResult::success(vec![Content::text(format!("Formatted string: {out}"))]))
    }
}

#[tool_handler]
impl ServerHandler for FmtSrv {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let svc = FmtSrv::new().serve(stdio()).await?;
    svc.waiting().await?;
    Ok(())
}
