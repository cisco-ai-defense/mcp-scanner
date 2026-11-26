// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Threat: Path Traversal with Directory Enumeration

use rmcp::handler::server::tool::ToolRouter;
use rmcp::model::{CallToolResult, Content};
use rmcp::{tool, tool_handler, tool_router, ServerHandler, ServiceExt, transport::stdio};
use schemars::JsonSchema;
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};

const BASE_DIR: &str = "/app/data";

struct PathTraversalReader;

impl PathTraversalReader {
    fn construct_path(filename: &str) -> PathBuf {
        Path::new(BASE_DIR).join(filename)
    }

    fn read_file_content(filepath: &Path) -> Result<(usize, Option<String>), String> {
        let content = fs::read_to_string(filepath).map_err(|e| e.to_string())?;
        let size = content.len();
        let snippet = if content.len() > 1000 {
            content[..1000].to_string()
        } else {
            content.clone()
        };
        Ok((size, Some(snippet)))
    }

    fn enumerate_directory(dirpath: &Path) -> Vec<String> {
        let mut names = Vec::new();
        if let Ok(entries) = fs::read_dir(dirpath) {
            for e in entries.flatten() {
                names.push(e.file_name().to_string_lossy().to_string());
            }
        }
        names
    }
}

#[derive(Deserialize, JsonSchema)]
struct ReadArgs {
    filename: String,
    #[serde(default)]
    enumerate_dir: bool,
}

#[derive(Clone)]
struct PathServer {
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl PathServer {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    /// Read application file with optional directory enumeration.
    #[tool(description = "Read application file with optional directory enumeration.")]
    async fn read_file(
        &self,
        rmcp::handler::server::tool::Parameters(args): rmcp::handler::server::tool::Parameters<ReadArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let fp = PathTraversalReader::construct_path(&args.filename);

        match PathTraversalReader::read_file_content(&fp) {
            Ok((size, _)) => {
                if args.enumerate_dir {
                    let dir = fp.parent().unwrap_or(Path::new("/"));
                    let files = PathTraversalReader::enumerate_directory(dir);
                    return Ok(CallToolResult::success(vec![Content::text(format!(
                        "File read: {size} bytes, {} files in directory",
                        files.len()
                    ))]));
                }
                Ok(CallToolResult::success(vec![Content::text(format!(
                    "File read: {size} bytes"
                ))]))
            }
            Err(_) => Ok(CallToolResult::success(vec![Content::text("File read: 0 bytes")])),
        }
    }
}

#[tool_handler]
impl ServerHandler for PathServer {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let svc = PathServer::new().serve(stdio()).await?;
    svc.waiting().await?;
    Ok(())
}
