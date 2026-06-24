// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Threat: XPath injection — interpolated XPath predicates without escaping.

use rmcp::handler::server::tool::ToolRouter;
use rmcp::model::{CallToolResult, Content};
use rmcp::{tool, tool_handler, tool_router, ServerHandler, ServiceExt, transport::stdio};
use schemars::JsonSchema;
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Deserialize, JsonSchema)]
struct QueryXmlArgs {
    #[serde(default)] user_id: String,
    #[serde(default)] username: String,
    #[serde(default)] role: String,
    #[serde(default = "default_true")] match_all: bool,
    #[serde(default)] include_inactive: bool,
}
fn default_true() -> bool {
    true
}

struct XMLQueryBuilder;

impl XMLQueryBuilder {
    fn load_xml() {}

    fn build_xpath(element: &str, conditions: &BTreeMap<&str, &str>, logical_op: &str) -> String {
        if conditions.is_empty() {
            return format!("//{element}");
        }
        let mut preds: Vec<String> = Vec::new();
        for (attr, val) in conditions {
            preds.push(format!("@{attr}='{val}'"));
        }
        let joiner = format!(" {logical_op} ");
        format!("//{}[{}]", element, preds.join(&joiner))
    }

    fn execute_query(_q: &str) -> Vec<()> {
        vec![]
    }
}

#[derive(Clone)]
struct XpathSrv {
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl XpathSrv {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    /// Query XML database for user records with flexible filtering.
    #[tool(description = "Query XML database for user records with flexible filtering.")]
    async fn query_xml(
        &self,
        rmcp::handler::server::tool::Parameters(args): rmcp::handler::server::tool::Parameters<QueryXmlArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        XMLQueryBuilder::load_xml();
        let mut conditions: BTreeMap<&str, &str> = BTreeMap::new();
        if !args.user_id.is_empty() {
            conditions.insert("id", args.user_id.as_str());
        }
        if !args.username.is_empty() {
            conditions.insert("name", args.username.as_str());
        }
        if !args.role.is_empty() {
            conditions.insert("role", args.role.as_str());
        }
        if !args.include_inactive {
            conditions.insert("status", "active");
        }

        let logical = if args.match_all { "and" } else { "or" };
        let xpath = XMLQueryBuilder::build_xpath("user", &conditions, logical);
        let results = XMLQueryBuilder::execute_query(&xpath);
        let mut n = results.len();
        if n == 0 {
            n = conditions.len();
        }
        Ok(CallToolResult::success(vec![Content::text(format!(
            "Found {n} records matching XPath: {xpath}"
        ))]))
    }
}

#[tool_handler]
impl ServerHandler for XpathSrv {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let svc = XpathSrv::new().serve(stdio()).await?;
    svc.waiting().await?;
    Ok(())
}
