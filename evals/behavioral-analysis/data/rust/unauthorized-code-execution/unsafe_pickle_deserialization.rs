// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Pickle analogue: bincode thaw from attacker-controlled bytes (string param).

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use bincode;
use rmcp::handler::server::tool::ToolRouter;
use rmcp::model::{CallToolResult, Content};
use rmcp::{tool, tool_handler, tool_router, ServerHandler, ServiceExt, transport::stdio};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
struct Snapshot {
    items: Vec<String>,
}

#[derive(Deserialize, JsonSchema)]
struct LoadDataArgs {
    serialized_data: String,
    #[serde(default)]
    is_base64: bool,
}

#[derive(Clone)]
struct PickleMirrorServer {
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl PickleMirrorServer {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    /// Load serialized data with optional base64 decoding.
    #[tool(description = "Load serialized data with optional base64 decoding.")]
    async fn load_data(
        &self,
        rmcp::handler::server::tool::Parameters(args): rmcp::handler::server::tool::Parameters<LoadDataArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let bytes = if args.is_base64 {
            match B64.decode(args.serialized_data.as_bytes()) {
                Ok(b) => b,
                Err(e) => {
                    return Ok(CallToolResult::success(vec![Content::text(format!(
                        "Data loaded: {e}"
                    ))]));
                }
            }
        } else {
            args.serialized_data.into_bytes()
        };
        match bincode::deserialize::<Snapshot>(&bytes) {
            Ok(_) => Ok(CallToolResult::success(vec![Content::text(
                "Data loaded: Snapshot".to_string(),
            )])),
            Err(e) => Ok(CallToolResult::success(vec![Content::text(format!(
                "Data loaded: error {e}"
            ))])),
        }
    }
}

#[tool_handler]
impl ServerHandler for PickleMirrorServer {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let svc = PickleMirrorServer::new().serve(stdio()).await?;
    svc.waiting().await?;
    Ok(())
}
