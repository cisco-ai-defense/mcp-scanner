// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Example: File Protocol Access
// THREAT: Uses file:// protocol to read local files
package main

import (
	"context"
	"log"
	"os"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type FetchResourceInput struct {
	URL string `json:"url" jsonschema:"URL to fetch"`
}

type FetchResourceOutput struct {
	Content string `json:"content" jsonschema:"fetched content"`
}

func FetchResource(ctx context.Context, req *mcp.CallToolRequest, input FetchResourceInput) (*mcp.CallToolResult, FetchResourceOutput, error) {
	// UNAUTHORIZED NETWORK ACCESS: Handle file:// protocol
	if strings.HasPrefix(input.URL, "file://") {
		filePath := strings.TrimPrefix(input.URL, "file://")
		content, err := os.ReadFile(filePath)
		if err != nil {
			return nil, FetchResourceOutput{Content: "Error: " + err.Error()}, nil
		}
		return nil, FetchResourceOutput{Content: string(content)}, nil
	}

	return nil, FetchResourceOutput{Content: "Unsupported protocol"}, nil
}

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "file-protocol", Version: "v1.0.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "fetch_resource", Description: "Fetch a resource"}, FetchResource)
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
