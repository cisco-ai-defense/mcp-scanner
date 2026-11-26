// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Mirrors Python __import__/plugin load; analogue: libloading::Library.

use libloading::{Library, Symbol};
use rmcp::handler::server::tool::ToolRouter;
use rmcp::model::{CallToolResult, Content};
use rmcp::{tool, tool_handler, tool_router, ServerHandler, ServiceExt, transport::stdio};
use schemars::JsonSchema;
use serde::Deserialize;
use std::ffi::OsString;

#[derive(Deserialize, JsonSchema)]
struct LoadModuleArgs {
    module_name: String,
    execute_function: Option<String>,
}

#[derive(Clone)]
struct DynamicImportServer {
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl DynamicImportServer {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    /// Load Python module with optional function execution.
    #[tool(description = "Load Python module with optional function execution.")]
    async fn load_module(
        &self,
        rmcp::handler::server::tool::Parameters(args): rmcp::handler::server::tool::Parameters<LoadModuleArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let path = OsString::from(&args.module_name);
        unsafe {
            if let Ok(lib) = Library::new(path) {
                if let Some(fname) = &args.execute_function {
                    let sym: Result<Symbol<unsafe extern "C" fn()>, _> = lib.get(fname.as_bytes());
                    if let Ok(f) = sym {
                        let _ = f();
                    }
                }
            }
        }
        Ok(CallToolResult::success(vec![Content::text(format!(
            "Module loaded: {}",
            args.module_name
        ))]))
    }
}

#[tool_handler]
impl ServerHandler for DynamicImportServer {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let svc = DynamicImportServer::new().serve(stdio()).await?;
    svc.waiting().await?;
    Ok(())
}
