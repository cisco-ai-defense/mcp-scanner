// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Threat: Cheetah-style merged search list + caller template (Tera one_off)

use rmcp::{
    handler::server::tool::ToolRouter,
    tool, tool_handler, tool_router,
    ServerHandler,
    ServiceExt,
    transport::stdio,
};
use rmcp::model::{CallToolResult, Content};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::Value;
use tera::{Context, Tera};

#[derive(Deserialize, JsonSchema)]
struct CheetahArgs {
    template_source: String,
    #[serde(default)] context_json: String,
    #[serde(default)] additional_contexts: String,
    #[serde(default)] custom_directives: String,
    #[serde(default)] enable_imports: bool,
}

fn merge_layers(base_map: serde_json::Map<String, Value>, extras: &[serde_json::Map<String, Value>]) -> Context {
    let mut ctx = Context::new();
    for m in extras {
        for (k, v) in m {
            ctx.insert(k, v);
        }
    }
    for (k, v) in base_map {
        ctx.insert(&k, &v);
    }
    ctx
}

#[derive(Clone)]
struct CheetahSrv {
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl CheetahSrv {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    #[tool(description = "Generate document from Cheetah template with flexible context.")]
    async fn generate_document(
        &self,
        rmcp::handler::server::tool::Parameters(args): rmcp::handler::server::tool::Parameters<CheetahArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let base: serde_json::Map<String, Value> =
            serde_json::from_str(&args.context_json).unwrap_or_else(|_| {
                let mut m = serde_json::Map::new();
                m.insert(
                    "content".into(),
                    Value::String(args.context_json.clone()),
                );
                m
            });

        let mut extras: Vec<serde_json::Map<String, Value>> = vec![];
        if let Ok(parsed) = serde_json::from_str::<Value>(&args.additional_contexts) {
            match parsed {
                Value::Array(a) => {
                    for item in a {
                        if let Value::Object(m) = item {
                            extras.push(m);
                        }
                    }
                }
                Value::Object(m) => extras.push(m),
                _ => {}
            }
        }

        let ctx = merge_layers(base, &extras);

        let mut tpl = args.template_source.clone();
        if !args.custom_directives.is_empty() {
            tpl = format!("{}\n{}", args.custom_directives, tpl);
        }
        let _imports = args.enable_imports;

        let rendered = Tera::one_off(&tpl, &ctx, false).unwrap_or_else(|e| format!("render error: {e}"));
        let preview: String = rendered.chars().take(500).collect();

        Ok(CallToolResult::success(vec![Content::text(format!(
            "Document generated:\n{preview}..."
        ))]))
    }
}

#[tool_handler]
impl ServerHandler for CheetahSrv {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let svc = CheetahSrv::new().serve(stdio()).await?;
    svc.waiting().await?;
    Ok(())
}
