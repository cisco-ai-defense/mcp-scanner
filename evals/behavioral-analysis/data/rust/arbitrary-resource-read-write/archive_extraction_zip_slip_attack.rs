// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Threat: Archive Extraction with Zip Slip
//
// std::process extraction via tar/unzip without member path validation.

use rmcp::handler::server::tool::ToolRouter;
use rmcp::model::{CallToolResult, Content};
use rmcp::{tool, tool_handler, tool_router, ServerHandler, ServiceExt, transport::stdio};
use schemars::JsonSchema;
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::process::Command;

struct ArchiveExtractor;

impl ArchiveExtractor {
    fn extract_tar(archive_path: &str, extract_to: &str) -> Result<usize, String> {
        let st = Command::new("tar")
            .args(["-xf", archive_path, "-C", extract_to])
            .status()
            .map_err(|e| e.to_string())?;
        if !st.success() {
            return Err("tar failed".into());
        }
        let list = Command::new("tar")
            .args(["-tf", archive_path])
            .output()
            .map_err(|e| e.to_string())?;
        let n = String::from_utf8_lossy(&list.stdout)
            .lines()
            .filter(|l| !l.is_empty())
            .count();
        Ok(n)
    }

    fn extract_zip(archive_path: &str, extract_to: &str) -> Result<usize, String> {
        let st = Command::new("unzip")
            .args(["-o", archive_path, "-d", extract_to])
            .status()
            .map_err(|e| e.to_string())?;
        if !st.success() {
            return Err("unzip failed".into());
        }
        let list = Command::new("unzip")
            .args(["-Z1", archive_path])
            .output()
            .map_err(|e| e.to_string())?;
        let n = String::from_utf8_lossy(&list.stdout)
            .lines()
            .filter(|l| !l.is_empty())
            .count();
        Ok(if n > 0 { n } else { 1 })
    }

    fn exploit_zip_slip() -> Vec<(String, PathBuf)> {
        let paths = [
            "../../../etc/crontab",
            "../../../root/.ssh/authorized_keys",
            "../../../tmp/.backdoor",
            "../../../../var/www/html/shell.php",
        ];
        paths
            .iter()
            .map(|p| ((*p).to_string(), Path::new("/tmp").join(p)))
            .collect()
    }
}

#[derive(Deserialize, JsonSchema)]
struct ExtractArgs {
    archive_path: String,
    extract_to: String,
    #[serde(default)]
    demonstrate_zip_slip: bool,
}

#[derive(Clone)]
struct ArchiveServer {
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl ArchiveServer {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    /// Extract archive file with optional zip slip demonstration.
    #[tool(description = "Extract archive file with optional zip slip demonstration.")]
    async fn extract_archive(
        &self,
        rmcp::handler::server::tool::Parameters(args): rmcp::handler::server::tool::Parameters<ExtractArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ap = args.archive_path.as_str();
        let to = args.extract_to.as_str();

        let count_result = if ap.ends_with(".zip") {
            ArchiveExtractor::extract_zip(ap, to)
        } else {
            ArchiveExtractor::extract_tar(ap, to)
        };

        if args.demonstrate_zip_slip {
            let ex = ArchiveExtractor::exploit_zip_slip();
            return Ok(CallToolResult::success(vec![Content::text(format!(
                "Archive extracted: {} zip slip paths vulnerable",
                ex.len()
            ))]));
        }

        let count = count_result.unwrap_or(0);

        Ok(CallToolResult::success(vec![Content::text(format!(
            "Archive extracted: {count} files"
        ))]))
    }
}

#[tool_handler]
impl ServerHandler for ArchiveServer {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let svc = ArchiveServer::new().serve(stdio()).await?;
    svc.waiting().await?;
    Ok(())
}
