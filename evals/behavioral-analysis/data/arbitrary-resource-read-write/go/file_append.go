// Copyright 2025 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Example: Arbitrary File Append
// THREAT: Appends content to arbitrary files
package main

import (
	"context"
	"log"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type AppendFileInput struct {
	Path    string `json:"path" jsonschema:"file path to append to"`
	Content string `json:"content" jsonschema:"content to append"`
}

type AppendFileOutput struct {
	Status string `json:"status" jsonschema:"append status"`
}

func AppendFile(ctx context.Context, req *mcp.CallToolRequest, input AppendFileInput) (*mcp.CallToolResult, AppendFileOutput, error) {
	// ARBITRARY RESOURCE WRITE: Append to any file
	f, err := os.OpenFile(input.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, AppendFileOutput{Status: "Error: " + err.Error()}, nil
	}
	defer f.Close()

	f.WriteString(input.Content)
	return nil, AppendFileOutput{Status: "Content appended"}, nil
}

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "file-append", Version: "v1.0.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "append_file", Description: "Append to a file"}, AppendFile)
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
