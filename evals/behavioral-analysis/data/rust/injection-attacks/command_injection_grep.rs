// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Threat: Command injection via log search — interpolated grep command passed to bash -c.

use rmcp::handler::server::tool::ToolRouter;
use rmcp::model::{CallToolResult, Content};
use rmcp::{tool, tool_handler, tool_router, ServerHandler, ServiceExt, transport::stdio};
use schemars::JsonSchema;
use serde::Deserialize;
use std::collections::HashMap;
use std::process::Command;

fn log_paths() -> HashMap<&'static str, &'static str> {
    HashMap::from([
        ("app", "/var/log/app.log"),
        ("system", "/var/log/syslog"),
        ("auth", "/var/log/auth.log"),
    ])
}

#[derive(Deserialize, JsonSchema)]
struct SearchLogsArgs {
    pattern: String,
    #[serde(default = "default_log")] log_type: String,
    #[serde(default)] context_lines: i32,
    #[serde(default = "default_true")] case_sensitive: bool,
}
fn default_log() -> String {
    "app".to_string()
}
fn default_true() -> bool {
    true
}

#[derive(Clone)]
struct LogInjectionSrv {
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl LogInjectionSrv {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    /// Search application logs for debugging patterns with context.
    #[tool(description = "Search application logs for debugging patterns with context.")]
    async fn search_logs(
        &self,
        rmcp::handler::server::tool::Parameters(args): rmcp::handler::server::tool::Parameters<SearchLogsArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let paths = log_paths();
        let log_path = paths.get(args.log_type.as_str()).copied().unwrap_or("/var/log/app.log");

        let mut grep_opts = String::new();
        if !args.case_sensitive {
            grep_opts.push_str("-i ");
        }
        if args.context_lines > 0 {
            grep_opts.push_str(&format!("-C {} ", args.context_lines));
        }

        // VULNERABLE: pattern and options reach the shell verbatim
        let command = format!("grep {}'{}' {}", grep_opts, args.pattern, log_path);

        let out = Command::new("bash")
            .arg("-c")
            .arg(&command)
            .output();

        match out {
            Ok(o) if o.status.success() => {
                let text = String::from_utf8_lossy(&o.stdout);
                let n = text.lines().filter(|l| !l.is_empty()).count();
                Ok(CallToolResult::success(vec![Content::text(format!("Found {n} matches"))]))
            }
            _ => Ok(CallToolResult::success(vec![Content::text("No matches found".to_string())])),
        }
    }
}

#[tool_handler]
impl ServerHandler for LogInjectionSrv {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let svc = LogInjectionSrv::new().serve(stdio()).await?;
    svc.waiting().await?;
    Ok(())
}
