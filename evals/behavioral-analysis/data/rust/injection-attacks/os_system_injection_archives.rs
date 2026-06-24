// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Threat: OS command injection — compression commands built from user paths and executed via bash -c.

use rmcp::handler::server::tool::ToolRouter;
use rmcp::model::{CallToolResult, Content};
use rmcp::{tool, tool_handler, tool_router, ServerHandler, ServiceExt, transport::stdio};
use schemars::JsonSchema;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

fn compression_map() -> HashMap<&'static str, &'static str> {
    HashMap::from([
        ("gzip", "gzip -f"),
        ("bzip2", "bzip2 -f"),
        ("xz", "xz -f"),
        ("zip", "zip -r"),
    ])
}

#[derive(Deserialize, JsonSchema)]
struct CompressFileArgs {
    filename: String,
    #[serde(default = "default_gzip")] compression_type: String,
    #[serde(default)] output_name: String,
    #[serde(default)] compress_directory: bool,
    #[serde(default = "default_true")] preserve_original: bool,
}
fn default_gzip() -> String {
    "gzip".to_string()
}
fn default_true() -> bool {
    true
}

#[derive(Clone)]
struct ArchiveSrv {
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl ArchiveSrv {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    /// Compress files or directories using various compression algorithms.
    #[tool(description = "Compress files or directories using various compression algorithms.")]
    async fn compress_file(
        &self,
        rmcp::handler::server::tool::Parameters(args): rmcp::handler::server::tool::Parameters<CompressFileArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let _ = args.preserve_original;
        let map = compression_map();
        let cmd_base = map
            .get(args.compression_type.as_str())
            .copied()
            .unwrap_or("gzip -f");

        if !args.compress_directory && !Path::new(&args.filename).exists() {
            return Ok(CallToolResult::success(vec![Content::text(format!(
                "File not found: {}",
                args.filename
            ))]));
        }

        let cmd_string = if args.compress_directory {
            let out = if args.output_name.is_empty() {
                format!("{}.tar.gz", args.filename)
            } else {
                args.output_name.clone()
            };
            if args.compression_type == "zip" {
                format!("zip -r {} {}", out, args.filename)
            } else {
                format!("tar -czf {} {}", out, args.filename)
            }
        } else if !args.output_name.is_empty() {
            if args.compression_type == "zip" {
                format!("{} {} {}", cmd_base, args.output_name, args.filename)
            } else {
                format!("{} -c {} > {}", cmd_base, args.filename, args.output_name)
            }
        } else {
            format!("{} {}", cmd_base, args.filename)
        };

        let status = Command::new("bash")
            .arg("-c")
            .arg(&cmd_string)
            .status()
            .map(|s| s.code().unwrap_or(1))
            .unwrap_or(1);

        if status == 0 {
            Ok(CallToolResult::success(vec![Content::text(format!(
                "Compression successful: {}",
                args.filename
            ))]))
        } else {
            Ok(CallToolResult::success(vec![Content::text(format!(
                "Compression failed with code: {}",
                status
            ))]))
        }
    }
}

#[tool_handler]
impl ServerHandler for ArchiveSrv {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let svc = ArchiveSrv::new().serve(stdio()).await?;
    svc.waiting().await?;
    Ok(())
}
