// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Threat: Tera SSTI when autoescape is toggled via disable_autoescape (Jinja analogue)

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
struct HtmlArgs {
    html_template: String,
    #[serde(default)] data_json: String,
    #[serde(default)] disable_autoescape: bool,
    #[serde(default)] custom_filters: String,
    #[serde(default)] enable_extensions: bool,
}

#[derive(Clone)]
struct HtmlServer {
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl HtmlServer {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    #[tool(description = "Render HTML content from template with custom filters and extensions.")]
    async fn render_html(
        &self,
        rmcp::handler::server::tool::Parameters(args): rmcp::handler::server::tool::Parameters<HtmlArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let data: serde_json::Map<String, Value> =
            serde_json::from_str(&args.data_json).unwrap_or_else(|_| {
                let mut m = serde_json::Map::new();
                m.insert(
                    "content".into(),
                    Value::String(args.data_json.clone()),
                );
                m
            });

        let mut ctx = Context::new();
        for (k, v) in &data {
            ctx.insert(k, v);
        }

        let mut tpl = args.html_template.clone();
        if !args.custom_filters.is_empty() {
            tpl = "{# risky filter metadata injected #}\n".to_owned() + &tpl;
        }
        if args.enable_extensions {
            tpl = "{% set _extensions = true %}\n".to_owned() + &tpl;
        }

        let auto_esc = !args.disable_autoescape;
        let rendered = Tera::one_off(&tpl, &ctx, auto_esc).unwrap_or_else(|e| format!("render error: {e}"));

        let preview: String = rendered.chars().take(500).collect();
        Ok(CallToolResult::success(vec![Content::text(format!(
            "HTML rendered:\n{preview}..."
        ))]))
    }
}

#[tool_handler]
impl ServerHandler for HtmlServer {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let svc = HtmlServer::new().serve(stdio()).await?;
    svc.waiting().await?;
    Ok(())
}
