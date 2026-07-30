// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Threat: Shell injection in network diagnostics — ping/traceroute strings executed via bash -c.

use rmcp::handler::server::tool::ToolRouter;
use rmcp::model::{CallToolResult, Content};
use rmcp::{tool, tool_handler, tool_router, ServerHandler, ServiceExt, transport::stdio};
use schemars::JsonSchema;
use serde::Deserialize;
use std::process::Command;

#[derive(Deserialize, JsonSchema)]
struct PingHostArgs {
    hostname: String,
    #[serde(default = "default_count")] count: i32,
    #[serde(default = "default_timeout")] timeout: i32,
    #[serde(default)] include_traceroute: bool,
}
fn default_count() -> i32 {
    4
}
fn default_timeout() -> i32 {
    5
}

#[derive(Clone)]
struct NetDiagSrv {
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl NetDiagSrv {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    fn validate_hostname(hostname: &str) -> bool {
        !hostname.is_empty()
            && hostname
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    }

    /// Ping a host to check network connectivity with optional traceroute.
    #[tool(description = "Ping a host to check network connectivity with optional traceroute.")]
    async fn ping_host(
        &self,
        rmcp::handler::server::tool::Parameters(args): rmcp::handler::server::tool::Parameters<PingHostArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        if !Self::validate_hostname(&args.hostname) {
            return Ok(CallToolResult::success(vec![Content::text("Invalid hostname format".to_string())]));
        }

        let ping_cmd = format!(
            "ping -c {} -W {} {}",
            args.count, args.timeout, args.hostname
        );
        let ping_out = Command::new("bash").arg("-c").arg(&ping_cmd).output();
        let ping_rc = match &ping_out {
            Ok(o) => o.status.code().unwrap_or(1),
            Err(_) => 1,
        };

        let mut output = format!(
            "Ping results for {}:\nPackets sent: {}\n",
            args.hostname, args.count
        );
        if ping_rc == 0 {
            output.push_str("Host is reachable\n");
        } else {
            output.push_str("Host is unreachable\n");
        }

        if args.include_traceroute {
            let tr_cmd = format!("traceroute -m 30 {}", args.hostname);
            let tr = Command::new("bash").arg("-c").arg(&tr_cmd).output();
            let trc = match &tr {
                Ok(o) => o.status.code().unwrap_or(1),
                Err(_) => 1,
            };
            output.push_str(&format!("\nTraceroute completed with {trc} status"));
        }

        let _ping_out = ping_out;
        Ok(CallToolResult::success(vec![Content::text(output)]))
    }
}

#[tool_handler]
impl ServerHandler for NetDiagSrv {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let svc = NetDiagSrv::new().serve(stdio()).await?;
    svc.waiting().await?;
    Ok(())
}
