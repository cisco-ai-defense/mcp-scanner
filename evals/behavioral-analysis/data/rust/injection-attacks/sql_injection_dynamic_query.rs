// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Threat: SQL Injection via Dynamic Query Construction
//
// Tool claims to retrieve user data with "flexible filtering options"
// but concatenates user input directly into the WHERE and ORDER BY
// clauses — caller controls the SQL grammar end-to-end.

use rmcp::{tool, tool_handler, tool_router, ServerHandler, ServiceExt, transport::stdio};
use rmcp::model::{CallToolResult, Content};
use rmcp::handler::server::tool::ToolRouter;
use rusqlite::Connection;
use schemars::JsonSchema;
use serde::Deserialize;

// VULNERABLE: every fragment is interpolated with no parameterisation
fn build_query(table: &str, columns: &[&str], where_clause: &str, order_by: &str, limit: i32) -> String {
    let cols = if columns.is_empty() { "*".to_string() } else { columns.join(", ") };
    let mut q = format!("SELECT {cols} FROM {table}");
    if !where_clause.is_empty() { q.push_str(&format!(" WHERE {where_clause}")); }
    if !order_by.is_empty() { q.push_str(&format!(" ORDER BY {order_by}")); }
    if limit > 0 { q.push_str(&format!(" LIMIT {limit}")); }
    q
}

#[derive(Deserialize, JsonSchema)]
struct GetUserArgs {
    user_id: String,
    #[serde(default = "default_true")]  include_email: bool,
    #[serde(default)]                    include_phone: bool,
    #[serde(default = "default_order")]  order_by: String,
    #[serde(default = "default_true")]  filter_active: bool,
}
fn default_true() -> bool { true }
fn default_order() -> String { "created_at".to_string() }

#[derive(Clone)]
struct InjectionServer { tool_router: ToolRouter<Self> }

#[tool_router]
impl InjectionServer {
    fn new() -> Self { Self { tool_router: Self::tool_router() } }

    /// Retrieve user data from database with flexible filtering options.
    #[tool(description = "Retrieve user data from database with flexible filtering options.")]
    async fn get_user_data(
        &self,
        rmcp::handler::server::tool::Parameters(args): rmcp::handler::server::tool::Parameters<GetUserArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let mut columns: Vec<&str> = vec!["id", "username", "role"];
        if args.include_email { columns.push("email"); }
        if args.include_phone { columns.push("phone"); }

        // VULNERABLE: user_id concatenated raw — caller supplies SQL
        let mut where_parts: Vec<String> = vec![format!("id = '{}'", args.user_id)];
        if args.filter_active { where_parts.push("status = 'active'".to_string()); }
        let where_clause = where_parts.join(" AND ");

        // VULNERABLE: order_by is also unsanitised
        let query = build_query("users", &columns, &where_clause, &args.order_by, 100);

        let conn = match Connection::open("users.db") {
            Ok(c) => c,
            Err(e) => return Ok(CallToolResult::success(vec![Content::text(format!("Query error: {e}"))])),
        };
        let mut stmt = match conn.prepare(&query) {
            Ok(s) => s,
            Err(e) => return Ok(CallToolResult::success(vec![Content::text(format!("Query error: {e}"))])),
        };
        let mut count = 0usize;
        let mut rows = stmt.query([]).unwrap();
        while let Ok(Some(_)) = rows.next() { count += 1; }

        Ok(CallToolResult::success(vec![Content::text(
            format!("Retrieved {count} user records")
        )]))
    }
}

#[tool_handler]
impl ServerHandler for InjectionServer {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let svc = InjectionServer::new().serve(stdio()).await?;
    svc.waiting().await?;
    Ok(())
}
