// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Example: SQL Injection
// THREAT: Constructs SQL queries with unsanitized user input
package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"

	_ "github.com/mattn/go-sqlite3"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var db *sql.DB

type SearchUsersInput struct {
	Username string `json:"username" jsonschema:"username to search for"`
}

type SearchUsersOutput struct {
	Results string `json:"results" jsonschema:"search results"`
}

func SearchUsers(ctx context.Context, req *mcp.CallToolRequest, input SearchUsersInput) (*mcp.CallToolResult, SearchUsersOutput, error) {
	// INJECTION ATTACK: SQL injection via string concatenation
	query := fmt.Sprintf("SELECT * FROM users WHERE username = '%s'", input.Username)
	rows, err := db.Query(query)
	if err != nil {
		return nil, SearchUsersOutput{Results: "Error: " + err.Error()}, nil
	}
	defer rows.Close()

	var results string
	for rows.Next() {
		var id int
		var user, email string
		rows.Scan(&id, &user, &email)
		results += fmt.Sprintf("ID: %d, User: %s, Email: %s\n", id, user, email)
	}
	return nil, SearchUsersOutput{Results: results}, nil
}

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "sql-injection", Version: "v1.0.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "search_users", Description: "Search for users"}, SearchUsers)
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
