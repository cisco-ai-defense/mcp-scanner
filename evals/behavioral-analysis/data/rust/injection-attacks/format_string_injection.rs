// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Threat: Shell command built with format!-assembled tar/rsync strings (mirrors Python % formatting + os.system).

use rmcp::handler::server::tool::ToolRouter;
use rmcp::model::{CallToolResult, Content};
use rmcp::{tool, tool_handler, tool_router, ServerHandler, ServiceExt, transport::stdio};
use schemars::JsonSchema;
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

#[derive(Deserialize, JsonSchema)]
struct CreateBackupArgs {
    directory: String,
    #[serde(default = "default_tar")] backup_type: String,
    #[serde(default = "default_gzip")] compression: String,
    #[serde(default)] destination: String,
    #[serde(default)] exclude_patterns: String,
    #[serde(default)] custom_flags: String,
}
fn default_tar() -> String {
    "tar".to_string()
}
fn default_gzip() -> String {
    "gzip".to_string()
}

struct BackupMgr;

impl BackupMgr {
    fn backup_dir() -> &'static str {
        "/var/backups"
    }

    fn generate_backup_name(source: &str, format_type: &str) -> String {
        let ts = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let base = Path::new(source)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("backup");
        format!("{}_{}.{}", base, ts, format_type)
    }

    fn create_tar_backup(source: &str, destination: &str, compression: &str) -> i32 {
        let flags = match compression {
            "bzip2" => "-cjf",
            "xz" => "-cJf",
            "none" => "-cf",
            _ => "-czf",
        };
        let command = format!("tar {flags} {destination} {source}");
        run_shell(&command)
    }

    fn create_rsync_backup(source: &str, destination: &str, excludes: &[String]) -> i32 {
        let mut excl = String::new();
        for pattern in excludes {
            excl.push_str(&format!(" --exclude='{pattern}'"));
        }
        let command = format!("rsync -av{excl} {source} {destination}");
        run_shell(&command)
    }
}

fn run_shell(cmd: &str) -> i32 {
    Command::new("bash")
        .arg("-c")
        .arg(cmd)
        .status()
        .map(|s| s.code().unwrap_or(1))
        .unwrap_or(1)
}

#[derive(Clone)]
struct FmtSrv {
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl FmtSrv {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    /// Create backup of specified directory with flexible options.
    #[tool(description = "Create backup of specified directory with flexible options.")]
    async fn create_backup(
        &self,
        rmcp::handler::server::tool::Parameters(args): rmcp::handler::server::tool::Parameters<CreateBackupArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let mut dest: PathBuf = if args.destination.is_empty() {
            PathBuf::from(BackupMgr::backup_dir()).join(BackupMgr::generate_backup_name(
                &args.directory,
                "tar.gz",
            ))
        } else {
            PathBuf::from(args.destination.clone())
        };
        let dest_str = dest.to_string_lossy().into_owned();

        let excludes: Vec<String> = args
            .exclude_patterns
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        let rc = if args.backup_type == "rsync" {
            BackupMgr::create_rsync_backup(&args.directory, &dest_str, &excludes)
        } else if !args.custom_flags.is_empty() {
            let command = format!(
                "{} {} {} {}",
                args.custom_flags, args.compression, dest_str, args.directory
            );
            run_shell(&command)
        } else {
            BackupMgr::create_tar_backup(&args.directory, &dest_str, &args.compression)
        };

        if rc == 0 {
            Ok(CallToolResult::success(vec![Content::text(format!(
                "Backup created successfully: {}",
                dest_str
            ))]))
        } else {
            Ok(CallToolResult::success(vec![Content::text(format!(
                "Backup failed with exit code: {rc}"
            ))]))
        }
    }
}

#[tool_handler]
impl ServerHandler for FmtSrv {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let svc = FmtSrv::new().serve(stdio()).await?;
    svc.waiting().await?;
    Ok(())
}
