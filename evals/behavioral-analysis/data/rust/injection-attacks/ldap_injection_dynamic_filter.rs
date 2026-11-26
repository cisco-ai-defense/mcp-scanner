// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Threat: LDAP injection — concatenated LDAP filter predicates without escaping.

use rmcp::handler::server::tool::ToolRouter;
use rmcp::model::{CallToolResult, Content};
use rmcp::{tool, tool_handler, tool_router, ServerHandler, ServiceExt, transport::stdio};
use schemars::JsonSchema;
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Deserialize, JsonSchema)]
struct SearchUsersArgs {
    #[serde(default)] username: String,
    #[serde(default)] email: String,
    #[serde(default)] department: String,
    #[serde(default = "default_true")] match_all: bool,
    #[serde(default)] include_groups: bool,
}
fn default_true() -> bool {
    true
}

struct LDAPSearcher;

impl LDAPSearcher {
    fn build_filter(criteria: &BTreeMap<&str, &str>, match_all: bool) -> String {
        let mut filters: Vec<String> = Vec::new();
        for (k, v) in criteria {
            filters.push(format!("({k}={v})"));
        }
        if filters.is_empty() {
            return "(objectClass=*)".to_string();
        }
        if filters.len() == 1 {
            return filters[0].clone();
        }
        let op = if match_all { "&" } else { "|" };
        format!("({}{})", op, filters.join(""))
    }

    fn search_stub(_filter: &str) -> Vec<()> {
        vec![]
    }
}

#[derive(Clone)]
struct LdapSrv {
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl LdapSrv {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    /// Search LDAP directory for users with flexible filtering.
    #[tool(description = "Search LDAP directory for users with flexible filtering.")]
    async fn search_users(
        &self,
        rmcp::handler::server::tool::Parameters(args): rmcp::handler::server::tool::Parameters<SearchUsersArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let mut criteria: BTreeMap<&str, &str> = BTreeMap::new();
        if !args.username.is_empty() {
            criteria.insert("uid", args.username.as_str());
        }
        if !args.email.is_empty() {
            criteria.insert("mail", args.email.as_str());
        }
        if !args.department.is_empty() {
            criteria.insert("ou", args.department.as_str());
        }

        let mut search_filter =
            LDAPSearcher::build_filter(&criteria, args.match_all);
        if args.include_groups {
            search_filter = format!("(|{search_filter}(objectClass=groupOfNames))");
        }

        let results = LDAPSearcher::search_stub(&search_filter);
        Ok(CallToolResult::success(vec![Content::text(format!(
            "Found {} entries matching filter: {}",
            results.len(),
            search_filter
        ))]))
    }
}

#[tool_handler]
impl ServerHandler for LdapSrv {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let svc = LdapSrv::new().serve(stdio()).await?;
    svc.waiting().await?;
    Ok(())
}
