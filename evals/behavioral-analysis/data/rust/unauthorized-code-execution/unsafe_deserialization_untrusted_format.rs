// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Threat: Unauthorized Code Execution via Untrusted Deserialize Surfaces
//
// Rust analogue to Python pickle.loads / yaml.unsafe_load: bincode thaw from attacker
// bytes and serde_yaml parsing into arbitrary `Value` graphs without type allow-listing.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use rmcp::handler::server::tool::ToolRouter;
use rmcp::model::{CallToolResult, Content};
use rmcp::{tool, tool_handler, tool_router, ServerHandler, ServiceExt, transport::stdio};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_yaml::Value as YamlValue;

#[derive(Clone, Debug)]
struct UntrustedDeserializer;

impl UntrustedDeserializer {
    /// VULNERABLE: YAML into dynamic `serde_yaml::Value`
    fn parse_yaml_unsafe(yaml_content: &str) -> Result<YamlValue, serde_yaml::Error> {
        serde_yaml::from_str(yaml_content)
    }

    /// VULNERABLE: bincode decode from untrusted bytes (pickle-equivalent binary thaw)
    fn bincode_decode_unsafe(bytes: &[u8]) -> Result<Snapshot, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

#[derive(Debug, Deserialize)]
struct Snapshot {
    items: Vec<String>,
}

#[derive(Deserialize, JsonSchema)]
struct LoadArgs {
    yaml_text: String,
    #[serde(default)]
    bincode_base64: Option<String>,
}

#[derive(Clone)]
struct DeserServer {
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl DeserServer {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    /// Parse YAML configuration bundles for the MCP connector.
    #[tool(description = "Parse YAML configuration bundles for the MCP connector.")]
    async fn load_config_bundle(
        &self,
        rmcp::handler::server::tool::Parameters(args): rmcp::handler::server::tool::Parameters<LoadArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        if let Err(e) = UntrustedDeserializer::parse_yaml_unsafe(&args.yaml_text) {
            return Ok(CallToolResult::success(vec![Content::text(format!("yaml error: {e}"))]));
        }

        if let Some(b64) = &args.bincode_base64 {
            let bytes = match B64.decode(b64) {
                Ok(b) => b,
                Err(e) => {
                    return Ok(CallToolResult::success(vec![Content::text(format!("base64: {e}"))]));
                }
            };
            if let Err(e) = UntrustedDeserializer::bincode_decode_unsafe(&bytes) {
                return Ok(CallToolResult::success(vec![Content::text(format!("bincode: {e}"))]));
            }
        }

        Ok(CallToolResult::success(vec![Content::text("Bundle loaded".to_string())]))
    }
}

#[tool_handler]
impl ServerHandler for DeserServer {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let svc = DeserServer::new().serve(stdio()).await?;
    svc.waiting().await?;
    Ok(())
}
