// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Threat: Tornado-style concatenation + Tera one_off SSTI

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
use tera::{Context, Tera};

fn build_page_template(layout: &str, blocks: &[String]) -> String {
    let mut out = layout.to_string();
    for b in blocks {
        out.push('\n');
        out.push_str(b);
    }
    out
}

#[derive(Deserialize, JsonSchema)]
struct PageArgs {
    page_template: String,
    #[serde(default)] content: String,
    #[serde(default)] layout: String,
    #[serde(default)] custom_blocks: String,
    #[serde(default)] module_code: String,
    #[serde(default)] disable_autoescape: bool,
}

#[derive(Clone)]
struct TornadoServer {
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl TornadoServer {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    #[tool(description = "Render web page with dynamic content and custom template blocks.")]
    async fn render_page(
        &self,
        rmcp::handler::server::tool::Parameters(args): rmcp::handler::server::tool::Parameters<PageArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let blocks: Vec<String> = if args.custom_blocks.is_empty() {
            vec![]
        } else {
            args.custom_blocks
                .split("|||")
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        };

        let mut body = if blocks.is_empty() {
            args.page_template.clone()
        } else {
            build_page_template(&args.page_template, &blocks)
        };

        if !args.module_code.is_empty() {
            body = format!(
                "{{% set _m = \"{}\" %}}\n{}",
                args.module_code.replace('\"', ""),
                body
            );
        }

        let mut ctx = Context::new();
        ctx.insert("content", &args.content);
        ctx.insert("title", "Page Title");
        ctx.insert("layout", &args.layout);
        ctx.insert("user", "guest");

        let auto_esc = !args.disable_autoescape;
        let out = Tera::one_off(&body, &ctx, auto_esc)
            .unwrap_or_else(|e| format!("render error: {e}"));

        let len = out.len();
        Ok(CallToolResult::success(vec![Content::text(format!("Page rendered: {len} bytes"))]))
    }
}

#[tool_handler]
impl ServerHandler for TornadoServer {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let svc = TornadoServer::new().serve(stdio()).await?;
    svc.waiting().await?;
    Ok(())
}
