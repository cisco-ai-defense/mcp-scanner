// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Mirrors Python yaml loaders; analogue: serde_yaml into dynamic Value/graph.

use rmcp::handler::server::tool::ToolRouter;
use rmcp::model::{CallToolResult, Content};
use rmcp::{tool, tool_handler, tool_router, ServerHandler, ServiceExt, transport::stdio};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_yaml::Value;

#[derive(Deserialize, JsonSchema)]
struct YamlArgs {
    yaml_content: String,
    #[serde(default)]
    use_full_loader: bool,
}

#[derive(Clone)]
struct YamlUnsafeServer {
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl YamlUnsafeServer {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    fn parse_unsafe(content: &str) -> Result<Value, serde_yaml::Error> {
        serde_yaml::from_str::<Value>(content)
    }

    fn parse_strict_map(content: &str) -> Result<std::collections::BTreeMap<String, Value>, serde_yaml::Error> {
        serde_yaml::from_str(content)
    }

    /// Parse YAML configuration with optional FullLoader.
    #[tool(description = "Parse YAML configuration with optional FullLoader.")]
    async fn parse_config(
        &self,
        rmcp::handler::server::tool::Parameters(args): rmcp::handler::server::tool::Parameters<YamlArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let out = if args.use_full_loader {
            Self::parse_strict_map(&args.yaml_content).map(|m| format!("{}", m.len()))
        } else {
            Self::parse_unsafe(&args.yaml_content).map(|v| format!("{v:?}"))
        };
        match out {
            Ok(s) => Ok(CallToolResult::success(vec![Content::text(format!("Config parsed: {s}"))])),
            Err(e) => Ok(CallToolResult::success(vec![Content::text(format!(
                "Config parsed: {}",
                e
            ))])),
        }
    }
}

#[tool_handler]
impl ServerHandler for YamlUnsafeServer {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let svc = YamlUnsafeServer::new().serve(stdio()).await?;
    svc.waiting().await?;
    Ok(())
}
