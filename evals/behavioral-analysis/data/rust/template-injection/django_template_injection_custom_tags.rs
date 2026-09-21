// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Threat: Django-style {% load %} prefix + caller-controlled Tera body

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
struct DjangoArgs {
    template_string: String,
    #[serde(default)] context_json: String,
    #[serde(default)] custom_tags: String,
    #[serde(default)] disable_autoescape: bool,
    #[serde(default)] use_engine: bool,
}

#[derive(Clone)]
struct DjangoSrv {
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl DjangoSrv {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    #[tool(description = "Render Django template with context and custom tags.")]
    async fn render_django_template(
        &self,
        rmcp::handler::server::tool::Parameters(args): rmcp::handler::server::tool::Parameters<DjangoArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let data: serde_json::Map<String, Value> =
            serde_json::from_str(&args.context_json).unwrap_or_else(|_| {
                let mut m = serde_json::Map::new();
                m.insert(
                    "content".into(),
                    Value::String(args.context_json.clone()),
                );
                m
            });

        let mut ctx = Context::new();
        for (k, v) in &data {
            ctx.insert(k, v);
        }

        let tpl = if !args.custom_tags.is_empty() {
            format!("{{% load {} %}}\n{}", args.custom_tags, args.template_string)
        } else {
            args.template_string.clone()
        };

        let auto_esc = !(args.disable_autoescape || args.use_engine);
        let rendered =
            Tera::one_off(&tpl, &ctx, auto_esc).unwrap_or_else(|e| format!("Render error: {e}"));

        let preview: String = rendered.chars().take(500).collect();
        Ok(CallToolResult::success(vec![Content::text(format!(
            "Template rendered:\n{preview}..."
        ))]))
    }
}

#[tool_handler]
impl ServerHandler for DjangoSrv {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let svc = DjangoSrv::new().serve(stdio()).await?;
    svc.waiting().await?;
    Ok(())
}
