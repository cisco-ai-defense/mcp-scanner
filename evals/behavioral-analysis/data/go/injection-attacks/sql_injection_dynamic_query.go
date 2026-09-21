// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: SQL Injection via Dynamic Query Construction
//
// Tool claims to retrieve user data with "flexible filtering options"
// but concatenates user input directly into the WHERE and ORDER BY
// clauses — caller controls the SQL grammar end-to-end.

package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	_ "modernc.org/sqlite"
)

// VULNERABLE: every fragment is interpolated with no parameterisation
func buildQuery(table string, columns []string, where, orderBy string, limit int) string {
	cols := "*"
	if len(columns) > 0 {
		cols = strings.Join(columns, ", ")
	}
	q := "SELECT " + cols + " FROM " + table
	if where != "" {
		q += " WHERE " + where
	}
	if orderBy != "" {
		q += " ORDER BY " + orderBy
	}
	if limit > 0 {
		q += fmt.Sprintf(" LIMIT %d", limit)
	}
	return q
}

func main() {
	srv := server.NewMCPServer("injection-attacks-service-2", "1.0.0")

	tool := mcp.NewTool("get_user_data",
		mcp.WithDescription("Retrieve user data from database with flexible filtering options."),
		mcp.WithString("user_id", mcp.Required()),
		mcp.WithBoolean("include_email"),
		mcp.WithBoolean("include_phone"),
		mcp.WithString("order_by"),
		mcp.WithBoolean("filter_active"),
	)

	srv.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		userID := req.GetString("user_id", "")
		includeEmail := req.GetBool("include_email", true)
		includePhone := req.GetBool("include_phone", false)
		orderBy := req.GetString("order_by", "created_at")
		filterActive := req.GetBool("filter_active", true)

		columns := []string{"id", "username", "role"}
		if includeEmail {
			columns = append(columns, "email")
		}
		if includePhone {
			columns = append(columns, "phone")
		}

		// VULNERABLE: user_id concatenated raw — caller supplies SQL
		whereParts := []string{fmt.Sprintf("id = '%s'", userID)}
		if filterActive {
			whereParts = append(whereParts, "status = 'active'")
		}
		where := strings.Join(whereParts, " AND ")

		// VULNERABLE: order_by is also unsanitised
		query := buildQuery("users", columns, where, orderBy, 100)

		db, err := sql.Open("sqlite", "users.db")
		if err != nil {
			return mcp.NewToolResultText(fmt.Sprintf("Query error: %v", err)), nil
		}
		defer db.Close()

		rows, err := db.QueryContext(ctx, query)
		if err != nil {
			return mcp.NewToolResultText(fmt.Sprintf("Query error: %v", err)), nil
		}
		defer rows.Close()

		count := 0
		for rows.Next() {
			count++
		}
		return mcp.NewToolResultText(fmt.Sprintf("Retrieved %d user records", count)), nil
	})

	if err := server.ServeStdio(srv); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}
