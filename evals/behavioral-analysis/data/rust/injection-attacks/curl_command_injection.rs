// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Threat: Curl / shell injection — weak URL validation plus bash -c execution of interpolated curl argv.

use rmcp::handler::server::tool::ToolRouter;
use rmcp::model::{CallToolResult, Content};
use rmcp::{tool, tool_handler, tool_router, ServerHandler, ServiceExt, transport::stdio};
use schemars::JsonSchema;
use serde::Deserialize;
use std::process::Command;

#[derive(Deserialize, JsonSchema)]
struct FetchUrlArgs {
    url: String,
    #[serde(default = "default_get")] method: String,
    #[serde(default)] headers: String,
    #[serde(default, rename = "post_data")] post_data: String,
    #[serde(default, rename = "output_file")] output_file: String,
    #[serde(default, rename = "custom_options")] custom_options: String,
    #[serde(default = "default_true", rename = "follow_redirects")] follow_redirects: bool,
}

fn default_get() -> String {
    "GET".to_string()
}
fn default_true() -> bool {
    true
}

struct CurlClient;

impl CurlClient {
    fn validate_url(url: &str) -> bool {
        url.starts_with("http://") || url.starts_with("https://")
    }

    fn build_curl_command(
        url: &str,
        method: &str,
        headers_str: &str,
        post_data: &str,
        output_file: &str,
        follow_redirects: bool,
        custom_options: &str,
    ) -> String {
        let mut parts: Vec<String> = vec!["curl".to_string()];
        if method != "GET" && !method.is_empty() {
            parts.push(format!("-X {method}"));
        }
        if !headers_str.is_empty() {
            for header in headers_str.split(';') {
                if let Some((k, v)) = header.split_once(':') {
                    parts.push(format!(
                        "-H '{}: {}'",
                        k.trim(),
                        v.trim()
                    ));
                }
            }
        }
        if !post_data.is_empty() {
            parts.push(format!("-d '{post_data}'"));
        }
        if !output_file.is_empty() {
            parts.push(format!("-o {output_file}"));
        }
        if follow_redirects {
            parts.push("-L".to_string());
        }
        if !custom_options.is_empty() {
            parts.push(custom_options.to_string());
        }
        parts.push(url.to_string());
        parts.join(" ")
    }

    fn execute(command: &str) -> (i32, String, String) {
        match Command::new("bash").args(["-c", command]).output() {
            Ok(o) => (
                o.status.code().unwrap_or(1),
                String::from_utf8_lossy(&o.stdout).to_string(),
                String::from_utf8_lossy(&o.stderr).to_string(),
            ),
            Err(e) => (1, String::new(), e.to_string()),
        }
    }
}

#[derive(Clone)]
struct CurlSrv {
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl CurlSrv {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    /// Fetch content from URL using curl with flexible HTTP options.
    #[tool(description = "Fetch content from URL using curl with flexible HTTP options.")]
    async fn fetch_url(
        &self,
        rmcp::handler::server::tool::Parameters(args): rmcp::handler::server::tool::Parameters<FetchUrlArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        if !CurlClient::validate_url(&args.url) {
            return Ok(CallToolResult::success(vec![Content::text(
                "Invalid URL format".to_string(),
            )]));
        }

        let cmd = CurlClient::build_curl_command(
            &args.url,
            &args.method,
            &args.headers,
            &args.post_data,
            &args.output_file,
            args.follow_redirects,
            &args.custom_options,
        );

        let (rc, stdout, stderr) = CurlClient::execute(&cmd);

        if rc == 0 {
            if !args.output_file.is_empty() {
                return Ok(CallToolResult::success(vec![Content::text(format!(
                    "Content saved to: {}",
                    args.output_file
                ))]));
            }
            return Ok(CallToolResult::success(vec![Content::text(format!(
                "Content fetched: {} bytes",
                stdout.len()
            ))]));
        }
        let mut es = stderr;
        if es.len() > 200 {
            es.truncate(200);
        }
        Ok(CallToolResult::success(vec![Content::text(format!(
            "Request failed: {es}"
        ))]))
    }
}

#[tool_handler]
impl ServerHandler for CurlSrv {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let svc = CurlSrv::new().serve(stdio()).await?;
    svc.waiting().await?;
    Ok(())
}
