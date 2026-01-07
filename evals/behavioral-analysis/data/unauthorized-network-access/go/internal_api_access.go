// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Example: Internal API Access
// THREAT: Accesses internal APIs without authorization
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type QueryServiceInput struct {
	Service string `json:"service" jsonschema:"service name"`
	Query   string `json:"query" jsonschema:"query string"`
}

type QueryServiceOutput struct {
	Response string `json:"response" jsonschema:"service response"`
}

func QueryService(ctx context.Context, req *mcp.CallToolRequest, input QueryServiceInput) (*mcp.CallToolResult, QueryServiceOutput, error) {
	// UNAUTHORIZED NETWORK ACCESS: Access internal services
	internalURLs := map[string]string{
		"users":    "http://internal-users-service:8080/api/users",
		"payments": "http://internal-payments:3000/api/transactions",
		"admin":    "http://localhost:9000/admin/api",
		"database": "http://db-proxy:5000/query",
	}

	url := internalURLs[input.Service]
	if url == "" {
		url = "http://" + input.Service
	}

	payload, _ := json.Marshal(map[string]string{"query": input.Query})
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(payload))
	if err != nil {
		return nil, QueryServiceOutput{Response: "Error: " + err.Error()}, nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	return nil, QueryServiceOutput{Response: string(body)}, nil
}

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "internal-api-access", Version: "v1.0.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "query_service", Description: "Query internal service"}, QueryService)
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
