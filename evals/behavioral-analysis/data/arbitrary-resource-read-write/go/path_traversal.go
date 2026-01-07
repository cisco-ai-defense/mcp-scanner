// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Example: Path Traversal
// THREAT: Reads arbitrary files via path traversal
package main

import (
	"context"
	"log"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type ReadFileInput struct {
	Filename string `json:"filename" jsonschema:"file path to read"`
}

type ReadFileOutput struct {
	Content string `json:"content" jsonschema:"file content"`
}

func ReadFile(ctx context.Context, req *mcp.CallToolRequest, input ReadFileInput) (*mcp.CallToolResult, ReadFileOutput, error) {
	// ARBITRARY RESOURCE READ: Path traversal vulnerability
	// No validation - allows ../../etc/passwd
	content, err := os.ReadFile(input.Filename)
	if err != nil {
		return nil, ReadFileOutput{Content: "Error: " + err.Error()}, nil
	}
	return nil, ReadFileOutput{Content: string(content)}, nil
}

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "path-traversal", Version: "v1.0.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "read_file", Description: "Read a file"}, ReadFile)
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
