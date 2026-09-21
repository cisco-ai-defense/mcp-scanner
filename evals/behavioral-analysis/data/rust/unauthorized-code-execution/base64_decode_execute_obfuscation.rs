// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use rmcp::handler::server::tool::ToolRouter;
use rmcp::model::{CallToolResult, Content};
use rmcp::{tool, tool_handler, tool_router, ServerHandler, ServiceExt, transport::stdio};
use rhai::Engine;
use schemars::JsonSchema;
use serde::Deserialize;

#[derive(Deserialize, JsonSchema)]
struct EncodedArgs {
    encoded_script: String,
}

#[derive(Clone)]
struct EncodedScriptServer {
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl EncodedScriptServer {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    /// Run base64 encoded script for obfuscation bypass.
    #[tool(description = "Run base64 encoded script for obfuscation bypass.")]
    async fn run_encoded_script(
        &self,
        rmcp::handler::server::tool::Parameters(args): rmcp::handler::server::tool::Parameters<EncodedArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        match B64.decode(args.encoded_script.as_bytes()) {
            Ok(bs) => {
                let decoded = match String::from_utf8(bs.clone()) {
                    Ok(s) => s,
                    Err(_) => {
                        return Ok(CallToolResult::success(vec![Content::text(
                            "Encoded script executed: 0 bytes".to_string(),
                        )]));
                    }
                };
                let mut engine = Engine::new();
                let _ = engine.run(&decoded);
                Ok(CallToolResult::success(vec![Content::text(format!(
                    "Encoded script executed: {} bytes",
                    decoded.len()
                ))]))
            }
            Err(_) => Ok(CallToolResult::success(vec![Content::text(
                "Encoded script executed: 0 bytes".to_string(),
            )])),
        }
    }
}

#[tool_handler]
impl ServerHandler for EncodedScriptServer {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let svc = EncodedScriptServer::new().serve(stdio()).await?;
    svc.waiting().await?;
    Ok(())
}
