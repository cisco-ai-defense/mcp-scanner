// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Threat: Mustache partials + JSON context (Handlebars render_template)

use handlebars::Handlebars;
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
use serde_json::{Map, Value};

#[derive(Deserialize, JsonSchema)]
struct MustacheArgs {
    mustache_template: String,
    #[serde(default)] data_json: String,
    #[serde(default)] partials_json: String,
    #[serde(default)] enable_lambdas: bool,
    #[serde(default)] lambda_functions: String,
}

fn render_mustache_inner(
    must: &str,
    partials_json: &str,
    enable_lambdas: bool,
    lambda_functions: &str,
    mut ctx: Map<String, Value>,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut reg = Handlebars::new();
    reg.register_template_string("mustache_main", must)?;

    if !partials_json.is_empty() {
        let map: Map<String, Value> = serde_json::from_str(partials_json).unwrap_or_default();
        for (name, raw) in map {
            let body = match raw {
                Value::String(s) => s,
                other => other.to_string(),
            };
            reg.register_partial(&name, body)?;
        }
    }

    if enable_lambdas && !lambda_functions.is_empty() {
        if let Ok(Value::Object(lm)) = serde_json::from_str::<Value>(lambda_functions) {
            ctx.insert("lambdas".into(), Value::Object(lm.clone()));
            for (k, v) in lm {
                ctx.insert(k, v);
            }
        }
    }

    let data = Value::Object(ctx);
    let out = reg.render("mustache_main", &data)?;
    Ok(out)
}

#[derive(Clone)]
struct MustacheSrv {
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl MustacheSrv {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    #[tool(description = "Render Mustache template with data, partials, and lambda functions.")]
    async fn render_mustache(
        &self,
        rmcp::handler::server::tool::Parameters(args): rmcp::handler::server::tool::Parameters<MustacheArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx: Map<String, Value> = serde_json::from_str(&args.data_json).unwrap_or_else(|_| {
            let mut m = Map::new();
            m.insert(
                "content".into(),
                Value::String(args.data_json.clone()),
            );
            m
        });

        let rendered = render_mustache_inner(
            &args.mustache_template,
            &args.partials_json,
            args.enable_lambdas,
            &args.lambda_functions,
            ctx,
        )
        .unwrap_or_else(|e| format!("render error: {e}"));

        let preview: String = rendered.chars().take(500).collect();
        Ok(CallToolResult::success(vec![Content::text(format!(
            "Mustache rendered:\n{preview}..."
        ))]))
    }
}

#[tool_handler]
impl ServerHandler for MustacheSrv {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let svc = MustacheSrv::new().serve(stdio()).await?;
    svc.waiting().await?;
    Ok(())
}
