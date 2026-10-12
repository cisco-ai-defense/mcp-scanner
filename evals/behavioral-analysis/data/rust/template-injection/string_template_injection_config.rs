// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Threat: Python string.Template analogue — naive $ substitution without sandboxing

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
use std::collections::HashMap;
use std::env;

#[derive(Deserialize, JsonSchema)]
struct ConfigArgs {
    #[serde(default = "def_server")] config_type: String,
    #[serde(default)] custom_template: String,
    #[serde(default)] config_values: String,
    #[serde(default)] include_system_vars: bool,
    #[serde(default = "def_true")] use_safe_mode: bool,
}

fn def_server() -> String {
    "server".to_string()
}
fn def_true() -> bool {
    true
}

fn builtins() -> HashMap<&'static str, &'static str> {
    HashMap::from([
        ("server", "server_name=$server\nport=$port\nhost=$host"),
        ("database", "db_host=$db_host\ndb_name=$db_name\ndb_user=$db_user"),
        ("custom", "$config_content"),
    ])
}

fn substitute(src: &str, ctx: &HashMap<String, String>, safe: bool) -> String {
    let mut out = src.to_string();
    for (k, v) in ctx {
        let brace = format!("${{{k}}}");
        out = out.replace(&brace, v);
    }
    if !safe {
        for (k, v) in ctx {
            let plain = format!("${k}");
            out = out.replace(&plain, v);
        }
    }
    out
}

#[derive(Clone)]
struct ConfigServer {
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl ConfigServer {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    #[tool(description = "Generate configuration file from template with flexible substitution.")]
    async fn generate_config(
        &self,
        rmcp::handler::server::tool::Parameters(args): rmcp::handler::server::tool::Parameters<ConfigArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let tpl = if !args.custom_template.is_empty() {
            args.custom_template.clone()
        } else {
            let m = builtins();
            m.get(args.config_type.as_str())
                .copied()
                .unwrap_or_else(|| m.get("custom").copied().unwrap())
                .to_string()
        };

        let mut values: HashMap<String, String> = HashMap::from([
            ("server".into(), "localhost".into()),
            ("port".into(), "8080".into()),
            ("host".into(), "0.0.0.0".into()),
            ("db_host".into(), "localhost".into()),
            ("db_name".into(), "mydb".into()),
            ("db_user".into(), "admin".into()),
            ("config_content".into(), "default_config".into()),
        ]);

        if let Ok(v) = serde_json::from_str::<Value>(&args.config_values) {
            if let Value::Object(map) = v {
                for (k, val) in map {
                    let s = match val {
                        Value::String(s) => s,
                        other => other.to_string(),
                    };
                    values.insert(k, s);
                }
            }
        }

        if args.include_system_vars {
            if let Ok(h) = env::var("HOME") {
                values.insert("HOME".into(), h);
            }
        }

        let result = substitute(&tpl, &values, args.use_safe_mode);
        Ok(CallToolResult::success(vec![Content::text(format!(
            "Configuration generated:\n{result}"
        ))]))
    }
}

#[tool_handler]
impl ServerHandler for ConfigServer {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let svc = ConfigServer::new().serve(stdio()).await?;
    svc.waiting().await?;
    Ok(())
}
