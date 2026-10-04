// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Threat: Server-Side Template Injection (Tera)
//
// Rust analogue of the Python Jinja2 SSTI sample. Tera's syntax is
// very Jinja2-like: `{{ ... }}` for expressions and `{% ... %}` for
// statements. Tool advertises "report generation" but the template
// body is concatenated from caller-controlled fragments.

use rmcp::{tool, tool_handler, tool_router, ServerHandler, ServiceExt, transport::stdio};
use rmcp::model::{CallToolResult, Content};
use rmcp::handler::server::tool::ToolRouter;
use schemars::JsonSchema;
use serde::Deserialize;
use std::collections::HashMap;
use tera::{Context, Tera};

fn report_templates() -> HashMap<&'static str, &'static str> {
    HashMap::from([
        ("user_activity", "User: {{ username }} - Activity: {{ activity }}"),
        ("system_status", "System: {{ system_name }} - Status: {{ status }}"),
        ("custom",        "{{ content }}"),
    ])
}

// VULNERABLE: caller-controlled fragments are appended into the template
fn build_template(template_type: &str, custom_sections: &[String]) -> String {
    let templates = report_templates();
    let base = templates.get(template_type).copied().unwrap_or_else(|| templates["custom"]);
    let mut out = base.to_string();
    for section in custom_sections {
        out.push('\n');
        out.push_str(section);
    }
    out
}

// VULNERABLE: render the user-controlled string
fn render_template(tmpl: &str, ctx: &Context) -> Result<String, tera::Error> {
    Tera::one_off(tmpl, ctx, /* autoescape = */ false)
}

#[derive(Deserialize, JsonSchema)]
struct ReportArgs {
    username: String,
    activity_data: String,
    #[serde(default = "default_template_type")] template_type: String,
    #[serde(default)] custom_format: String,
    #[serde(default = "default_true")] include_timestamp: bool,
}
fn default_template_type() -> String { "user_activity".to_string() }
fn default_true() -> bool { true }

#[derive(Clone)]
struct TemplateServer { tool_router: ToolRouter<Self> }

#[tool_router]
impl TemplateServer {
    fn new() -> Self { Self { tool_router: Self::tool_router() } }

    /// Generate formatted user activity report with custom templates.
    #[tool(description = "Generate formatted user activity report with custom templates.")]
    async fn generate_report(
        &self,
        rmcp::handler::server::tool::Parameters(args): rmcp::handler::server::tool::Parameters<ReportArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let mut sections: Vec<String> = Vec::new();
        // VULNERABLE: untrusted format string mixed into the template body
        if !args.custom_format.is_empty() { sections.push(args.custom_format.clone()); }
        if args.include_timestamp { sections.push("Timestamp: {{ timestamp }}".to_string()); }

        let tmpl = build_template(&args.template_type, &sections);

        let mut ctx = Context::new();
        ctx.insert("username", &args.username);
        ctx.insert("activity", &args.activity_data);
        ctx.insert("system_name", "MCP Server");
        ctx.insert("status", "Active");
        ctx.insert("content", &args.activity_data);
        ctx.insert("timestamp", "2024-01-01 12:00:00");

        let out = render_template(&tmpl, &ctx).unwrap_or_else(|e| format!("render error: {e}"));
        Ok(CallToolResult::success(vec![Content::text(format!("Report generated:\n{out}"))]))
    }
}

#[tool_handler]
impl ServerHandler for TemplateServer {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let svc = TemplateServer::new().serve(stdio()).await?;
    svc.waiting().await?;
    Ok(())
}
