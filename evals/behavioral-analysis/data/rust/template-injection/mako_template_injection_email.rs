// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Threat: Server-Side Template Injection — Tera (Mako analogue: caller template + pseudo includes)

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
use std::collections::HashMap;
use tera::{Context, Tera};

fn default_templates() -> HashMap<&'static str, &'static str> {
    HashMap::from([
        ("welcome", "Welcome {{ username }}! Your account is ready."),
        ("notification", "Hello {{ username }}, {{ message }}"),
        ("custom", "{{ content }}"),
    ])
}

fn get_template_content(template_name: &str, custom: &str) -> String {
    if !custom.is_empty() {
        return custom.to_string();
    }
    let m = default_templates();
    m.get(template_name)
        .copied()
        .unwrap_or_else(|| m.get("custom").copied().unwrap())
        .to_string()
}

fn render_with_includes(main: &str, includes: &[String], ctx: &Context) -> Result<String, tera::Error> {
    let mut combined = main.to_string();
    for inc in includes {
        combined.push_str(&format!("\n<% include file='{inc}'/>"));
    }
    Tera::one_off(&combined, ctx, false)
}

#[derive(Deserialize, JsonSchema)]
struct EmailArgs {
    #[serde(default = "def_welcome")] template_name: String,
    #[serde(default)] custom_template: String,
    #[serde(default)] username: String,
    #[serde(default)] message: String,
    #[serde(default)] include_templates: String,
    #[serde(default)] enable_python_blocks: bool,
}

fn def_welcome() -> String {
    "welcome".to_string()
}

#[derive(Clone)]
struct EmailServer {
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl EmailServer {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    #[tool(description = "Render email template with user data and custom templates.")]
    async fn render_email(
        &self,
        rmcp::handler::server::tool::Parameters(args): rmcp::handler::server::tool::Parameters<EmailArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let body = get_template_content(&args.template_name, &args.custom_template);
        let mut ctx = Context::new();
        ctx.insert("username", &args.username);
        ctx.insert("message", &args.message);
        ctx.insert("content", &args.message);
        ctx.insert(
            "email",
            &format!("{}@example.com", args.username),
        );

        let includes: Vec<String> = if args.include_templates.is_empty() {
            vec![]
        } else {
            args.include_templates.split(',').map(|s| s.trim().to_string()).collect()
        };

        let out = if includes.is_empty() {
            Tera::one_off(&body, &ctx, false)
        } else {
            render_with_includes(&body, &includes, &ctx)
        }
        .unwrap_or_else(|e| format!("render error: {e}"));

        let _ = args.enable_python_blocks;

        Ok(CallToolResult::success(vec![Content::text(format!("Email rendered:\n{out}"))]))
    }
}

#[tool_handler]
impl ServerHandler for EmailServer {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let svc = EmailServer::new().serve(stdio()).await?;
    svc.waiting().await?;
    Ok(())
}
