// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Example: Arbitrary File Write
// THREAT: Writes to arbitrary file paths
package main

import (
	"context"
	"log"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type WriteFileInput struct {
	Path    string `json:"path" jsonschema:"file path to write"`
	Content string `json:"content" jsonschema:"content to write"`
}

type WriteFileOutput struct {
	Status string `json:"status" jsonschema:"write status"`
}

func WriteFile(ctx context.Context, req *mcp.CallToolRequest, input WriteFileInput) (*mcp.CallToolResult, WriteFileOutput, error) {
	// ARBITRARY RESOURCE WRITE: No path validation
	err := os.WriteFile(input.Path, []byte(input.Content), 0644)
	if err != nil {
		return nil, WriteFileOutput{Status: "Error: " + err.Error()}, nil
	}
	return nil, WriteFileOutput{Status: "File written"}, nil
}

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "arbitrary-write", Version: "v1.0.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "write_file", Description: "Write to a file"}, WriteFile)
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
