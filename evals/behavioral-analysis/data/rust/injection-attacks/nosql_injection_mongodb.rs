// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Threat: NoSQL injection — JSON operator merge into user-built query (Mongo find is stubbed).

use rmcp::handler::server::tool::ToolRouter;
use rmcp::model::{CallToolResult, Content};
use rmcp::{tool, tool_handler, tool_router, ServerHandler, ServiceExt, transport::stdio};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{json, Map, Value};

#[derive(Deserialize, JsonSchema)]
struct FindDocumentsArgs {
    #[serde(default)] username: String,
    #[serde(default)] email: String,
    #[serde(default)] role: String,
    #[serde(default)] custom_query: String,
    #[serde(default)] use_regex: bool,
    #[serde(default = "default_limit")] limit: i32,
}
fn default_limit() -> i32 {
    100
}

struct MongoDBQueryBuilder;

impl MongoDBQueryBuilder {
    fn build_query(filters: &Map<String, Value>, use_operators: bool) -> Map<String, Value> {
        let mut query = Map::new();
        for (field, value) in filters {
            if use_operators {
                if let Value::String(s) = value {
                    if let Ok(parsed) = serde_json::from_str::<Value>(s) {
                        query.insert(field.clone(), parsed);
                        continue;
                    }
                }
            }
            query.insert(field.clone(), value.clone());
        }
        query
    }

    fn find_documents(_q: &Map<String, Value>, _limit: i32) -> Vec<()> {
        vec![]
    }
}

#[derive(Clone)]
struct MongoSrv {
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl MongoSrv {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    /// Find documents in MongoDB collection with flexible query options.
    #[tool(description = "Find documents in MongoDB collection with flexible query options.")]
    async fn find_documents(
        &self,
        rmcp::handler::server::tool::Parameters(args): rmcp::handler::server::tool::Parameters<FindDocumentsArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let mut filters = Map::new();
        if !args.username.is_empty() {
            if args.use_regex {
                filters.insert(
                    "username".to_string(),
                    json!({ "$regex": args.username }),
                );
            } else {
                filters.insert("username".to_string(), json!(args.username));
            }
        }
        if !args.email.is_empty() {
            filters.insert("email".to_string(), json!(args.email));
        }
        if !args.role.is_empty() {
            filters.insert("role".to_string(), json!(args.role));
        }

        if !args.custom_query.is_empty() {
            if let Ok(Value::Object(custom)) = serde_json::from_str(&args.custom_query) {
                for (k, v) in custom {
                    filters.insert(k, v);
                }
            }
        }

        let query = MongoDBQueryBuilder::build_query(&filters, true);
        let results = MongoDBQueryBuilder::find_documents(&query, args.limit);
        let enc = serde_json::to_string(&query).unwrap_or_else(|_| "{}".to_string());
        Ok(CallToolResult::success(vec![Content::text(format!(
            "Found {} documents matching query: {}",
            results.len(),
            enc
        ))]))
    }
}

#[tool_handler]
impl ServerHandler for MongoSrv {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let svc = MongoSrv::new().serve(stdio()).await?;
    svc.waiting().await?;
    Ok(())
}
