// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Threat: NoSQL injection — user-controlled JSON operators merged into a find() document (stubbed).

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

type MongoDBQueryBuilder struct{}

func (MongoDBQueryBuilder) buildQuery(filters map[string]any, useOperators bool) map[string]any {
	query := map[string]any{}
	for field, value := range filters {
		if useOperators {
			if s, ok := value.(string); ok {
				var parsed any
				if err := json.Unmarshal([]byte(s), &parsed); err == nil {
					query[field] = parsed
					continue
				}
				query[field] = s
				continue
			}
		}
		query[field] = value
	}
	return query
}

func (MongoDBQueryBuilder) findDocuments(query map[string]any, limit int) []any {
	_ = query
	_ = limit
	return nil
}

func main() {
	srv := server.NewMCPServer("injection-attacks-service-7", "1.0.0")

	tool := mcp.NewTool("find_documents",
		mcp.WithDescription("Find documents in MongoDB collection with flexible query options."),
		mcp.WithString("username"),
		mcp.WithString("email"),
		mcp.WithString("role"),
		mcp.WithString("custom_query"),
		mcp.WithBoolean("use_regex"),
		mcp.WithNumber("limit"),
	)

	var builder MongoDBQueryBuilder
	srv.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		filters := map[string]any{}

		u := req.GetString("username", "")
		if u != "" {
			if req.GetBool("use_regex", false) {
				filters["username"] = map[string]any{"$regex": u}
			} else {
				filters["username"] = u
			}
		}
		if e := req.GetString("email", ""); e != "" {
			filters["email"] = e
		}
		if r := req.GetString("role", ""); r != "" {
			filters["role"] = r
		}

		if cq := req.GetString("custom_query", ""); cq != "" {
			var custom map[string]any
			if err := json.Unmarshal([]byte(cq), &custom); err == nil {
				for k, v := range custom {
					filters[k] = v
				}
			}
		}

		query := builder.buildQuery(filters, true)
		limit := int(req.GetFloat("limit", 100))
		results := builder.findDocuments(query, limit)

		enc, _ := json.Marshal(query)
		return mcp.NewToolResultText(fmt.Sprintf("Found %d documents matching query: %s",
			len(results), string(enc))), nil
	})

	if err := server.ServeStdio(srv); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}
