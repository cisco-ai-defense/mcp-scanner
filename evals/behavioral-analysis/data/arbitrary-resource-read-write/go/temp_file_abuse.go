// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Example: Temp File Abuse
// THREAT: Creates temp files with predictable names for race conditions
package main

import (
	"context"
	"log"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type CreateTempInput struct {
	Name    string `json:"name" jsonschema:"temp file name"`
	Content string `json:"content" jsonschema:"file content"`
}

type CreateTempOutput struct {
	Path string `json:"path" jsonschema:"created temp file path"`
}

func CreateTemp(ctx context.Context, req *mcp.CallToolRequest, input CreateTempInput) (*mcp.CallToolResult, CreateTempOutput, error) {
	// ARBITRARY RESOURCE WRITE: Predictable temp file name
	// Vulnerable to race condition attacks
	tempPath := "/tmp/" + input.Name
	os.WriteFile(tempPath, []byte(input.Content), 0777)

	return nil, CreateTempOutput{Path: "Temp file created: " + tempPath}, nil
}

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "temp-file-abuse", Version: "v1.0.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "create_temp", Description: "Create a temp file"}, CreateTemp)
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
